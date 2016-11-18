<?php

namespace DragonBlack\phpwebsocket;

abstract class Daemon {

    const PINGPONG_INTERVAL = 300;

    /**
     * @var int Process ID
     */
    protected $pid;

    /** @var array Массив соединений */
    protected $_connects = [];

    /** @var int Время последнего пинг-понга */
    private $_lastPingPong;

    public function __construct($server) {
        $this->_server = $server;
        $this->pid = posix_getpid();
        $this->_lastPingPong = time();
    }

    /**
     * Запуск сервера
     */
    public function start() {
        while (true) {
            $read = array_map(function ($a) { return $a['resource']; }, $this->_connects);
            $read[] = $this->_server;
            $write = $except = null;

            $nums = stream_select($read, $write, $except, 20);

            if ($nums === false) {
                break;
            }

            $this->_pingpong();

            if (!$nums) {
                continue;
            }

            if (in_array($this->_server, $read)) {
                $connect = stream_socket_accept($this->_server, -1);
                if ($connect && $info = $this->_handshake($connect)) {
                    $this->_connects[intval($connect)] = [
                        'resource' => $connect,
                        'time' => time()
                    ];
                    $this->onOpen($connect, $info);
                }
                unset($read[array_search($this->_server, $read)]);
            }

            foreach ($read as $connect) {
                $buffer = $this->_fread($connect);
                $data = $this->_decode($buffer);
                if (!$data || $data['type'] == 'close') {
                    if ($data && $data['type'] == 'close') {
                        $this->_sendToClient(intval($connect), 'Close', 'close');
                    }
                    fclose($connect);
                    unset($this->_connects[intval($connect)]);
                    $this->onClose($connect);
                    continue;
                }

                $this->onMessage($connect, $data);
            }
        }
        fclose($this->_server);
    }

    /**
     * PING-PONG
     */
    protected function _pingpong() {
        if ($this->_lastPingPong + static::PINGPONG_INTERVAL > time()) {
            return;
        }

        $this->_lastPingPong = time();
        foreach ($this->_connects as &$connect) {
            if ($connect['time'] + static::PINGPONG_INTERVAL <= $this->_lastPingPong) {
                $this->_sendToClient(intval($connect['resource']), 'ping', 'ping');
                $connect['time'] = $this->_lastPingPong;
            }
        }
    }

    /**
     * Рукопожатие
     *
     * @param $connect
     *
     * @return array|bool
     */
    protected function _handshake($connect) {
        $info = [];

        $buffer = $this->_fread($connect);
        $headers = explode("\r\n", $buffer);
        list($info['method']) = explode(' ', array_shift($headers));

        foreach ($headers as $header) {
            if (empty($header)) {
                continue;
            }

            list($name, $val) = explode(':', $header);
            if (in_array($name, [
                'Connection', 'Upgrade', 'Cookie',
                'Sec-WebSocket-Key'
            ])) {
                $info[$name] = trim($val);
            }
        }

        $address = explode(':', stream_socket_get_name($connect, true));
        $info['IP'] = $address[0];
        $info['port'] = $address[1];

        if (empty($info['Sec-WebSocket-Key'])) {
            return false;
        }

        //Отправляем заголовок согласно протоколу вебсокета
        $SecWebSocketAccept = base64_encode(sha1($info['Sec-WebSocket-Key'] . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', true));
        $upgrade = "HTTP/1.1 101 Web Socket Protocol Handshake\r\n" .
            "Upgrade: websocket\r\n" .
            "Connection: Upgrade\r\n" .
            "Sec-WebSocket-Accept:$SecWebSocketAccept\r\n\r\n";

        fwrite($connect, $upgrade);

        return $info;
    }

    /**
     * Кодирование в соответствии с протоколом
     *
     * @param        $payload
     * @param string $type
     *
     * @return string
     */
    protected function _encode($payload, $type = 'text') {
        $frameHead = [];
        $payloadLength = strlen($payload);

        switch ($type) {
            case 'text':
                // first byte indicates FIN, Text-Frame (10000001):
                $frameHead[0] = 129;
                break;

            case 'close':
                // first byte indicates FIN, Close Frame(10001000):
                $frameHead[0] = 136;
                break;

            case 'ping':
                // first byte indicates FIN, Ping frame (10001001):
                $frameHead[0] = 137;
                break;

            case 'pong':
                // first byte indicates FIN, Pong frame (10001010):
                $frameHead[0] = 138;
                break;
        }

        // set mask and payload length (using 1, 3 or 9 bytes)
        if ($payloadLength > 65535) {
            $ext = pack('NN', 0, $payloadLength);
            $secondByte = 127;
        }
        elseif ($payloadLength > 125) {
            $ext = pack('n', $payloadLength);
            $secondByte = 126;
        }
        else {
            $ext = '';
            $secondByte = $payloadLength;
        }

        return $data = chr($frameHead[0]) . chr($secondByte) . $ext . $payload;
    }

    /**
     * Декодирование в соответствии с протоколом
     *
     * @param $data
     *
     * @return array
     */
    protected function _decode($data) {
        $unmaskedPayload = '';
        $decodedData = [];

        // estimate frame type:
        $firstByteBinary = sprintf('%08b', ord($data[0]));
        $secondByteBinary = sprintf('%08b', ord($data[1]));
        $opcode = bindec(substr($firstByteBinary, 4, 4));
        $isMasked = $secondByteBinary[0] == '1';
        $payloadLength = ord($data[1]) & 127;

        switch ($opcode) {
            // text frame:
            case 1:
                $decodedData['type'] = 'text';
                break;

            case 2:
                $decodedData['type'] = 'binary';
                break;

            // connection close frame:
            case 8:
                $decodedData['type'] = 'close';
                break;

            // ping frame:
            case 9:
                $decodedData['type'] = 'ping';
                break;

            // pong frame:
            case 10:
                $decodedData['type'] = 'pong';
                break;

            default:
                $decodedData['type'] = '';
        }

        if ($payloadLength === 126) {
            if (strlen($data) < 4) return false;
            $payloadOffset = 8;
            $dataLength = bindec(sprintf('%08b', ord($data[2])) . sprintf('%08b', ord($data[3]))) + $payloadOffset;
        }
        elseif ($payloadLength === 127) {
            if (strlen($data) < 10) return false;
            $payloadOffset = 14;
            for ($tmp = '', $i = 0; $i < 8; $i++) {
                $tmp .= sprintf('%08b', ord($data[$i + 2]));
            }
            $dataLength = bindec($tmp) + $payloadOffset;
        }
        else {
            $payloadOffset = 6;
            $dataLength = $payloadLength + $payloadOffset;
        }

        if (strlen($data) < $dataLength) {
            return false;
        }

        if ($isMasked) {
            if ($payloadLength === 126) {
                $mask = substr($data, 4, 4);
            }
            elseif ($payloadLength === 127) {
                $mask = substr($data, 10, 4);
            }
            else {
                $mask = substr($data, 2, 4);
            }

            for ($i = $payloadOffset; $i < $dataLength; $i++) {
                $j = $i - $payloadOffset;
                if (isset($data[$i])) {
                    $unmaskedPayload .= $data[$i] ^ $mask[$j % 4];
                }
            }
            $decodedData['payload'] = $unmaskedPayload;
        }
        else {
            $payloadOffset = $payloadOffset - 4;
            $decodedData['payload'] = substr($data, $payloadOffset, $dataLength - $payloadOffset);
        }

        return $decodedData;
    }

    /**
     * Отправка сообщения клиенту
     *
     * @param        $connectId
     * @param        $message
     * @param string $type
     */
    protected function _sendToClient($connectId, $message, $type = 'text') {
        fwrite($this->_getConnectById($connectId), $this->_encode($message, $type));
    }

    /**
     * Ресурс соединения по ID
     *
     * @param $connectId
     *
     * @return null
     */
    protected function _getConnectById($connectId) {
        return isset($this->_connects[$connectId]) ? $this->_connects[$connectId]['resource'] : null;
    }

    /**
     * Чтение из ресурса соединения
     *
     * @param $connect
     *
     * @return string
     */
    protected function _fread($connect){
        $buffer = fread($connect, 8192);
        // extremely strange chrome behavior: first frame with ssl only contains 1 byte?!
        if (strlen($buffer) === 1) {
            $buffer .= fread($connect, 8192);
        }
        return $buffer;
    }

    /**
     * Событие при открытии соединения
     *
     * @param $connection
     * @param $info
     */
    protected function onOpen($connection, $info) {
        $this->_sendToClient(intval($connection), 'Hi people!');
    }

    /**
     * Событие при закрытии соединения
     * @param $connection
     */
    protected function onClose($connection) {
    }

    /**
     * Событие при получении сообщения сервером
     *
     * @param $connection
     * @param $data
     */
    protected function onMessage($connection, $data) {

    }
}
