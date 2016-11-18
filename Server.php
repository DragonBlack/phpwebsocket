<?php
namespace dragonblack\phpwebsocket;


class Server {

    /** @var  string Путьк файлу сертификата */
    private $_cert;

    /** @var  string Путь к файлу секрктного ключа */
    private $_cert_key;

    /** @var  string Пароль к файлу секрктного ключа */
    private $_passphrase;

    /** @var bool Использовать SSH */
    private $_ssl = false;

    public function __construct($config) {
        //Windows не поддерживается
        if(strtolower(substr(PHP_OS, 0, 3)) == 'win'){
            die('"Must die" is not supported'.PHP_EOL);
        }

        //Проверка и установка настроек сертификата
        if (isset($config['ssl']) && $config['ssl'] === true) {
            if (empty($config['cert'])) {
                throw new WebsocketException('Not found SSL certificate file');
            }

            if (empty($config['cert_key'])) {
                throw new WebsocketException('Not found SSL certificate private key file');
            }

            if (!isset($config['cert_passphrase'])) {
                throw new WebsocketException('Need passphrase for certificate');
            }
            $this->_ssl = true;
            $this->_cert = $config['cert'];
            $this->_cert_key = $config['cert_key'];
            $this->_passphrase = $config['cert_passphrase'];
        }
        $this->config = $config;
    }

    /**
     * Старт сервера
     *
     * @throws WebsocketException
     */
    public function start() {
        $pid = @file_get_contents($this->config['pid']);
        if ($pid) {
            if (posix_getpgid($pid)) {
                die('Already started' . PHP_EOL);
            }
            else {
                unlink($this->config['pid']);
            }
        }

        if (empty($this->config['socket'])) {
            throw new WebsocketException('Error: Socket must be defined');
        }

        if ($this->_ssl) {
            $this->config['socket'] = 'tls://' . $this->config['socket'];
            $context = $this->applySSLContext();
            //Открываем сокет
            $server = stream_socket_server($this->config['socket'], $errorNumber, $errorString, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
        }
        else {
            $this->config['socket'] = 'tcp://' . $this->config['socket'];
            //Открываем сокет
            $server = stream_socket_server($this->config['socket'], $errorNumber, $errorString);
        }

        if (!$server) {
            die("Error: stream_socket_server: $errorString ($errorNumber)" . PHP_EOL);
        }

        file_put_contents($this->config['pid'], posix_getpid());

        $workerClass = $this->config['class'];
        $worker = new $workerClass($server);
        $worker->start();
    }

    /**
     * Настройки SSH
     * @return resource
     */
    private function applySSLContext() {
        $context = stream_context_create();

        // apply ssl context:
        stream_context_set_option($context, 'ssl', 'local_cert', $this->_cert);
        stream_context_set_option($context, 'ssl', 'local_pk', $this->_cert_key);
        stream_context_set_option($context, 'ssl', 'passphrase', $this->_passphrase);
        stream_context_set_option($context, 'ssl', 'allow_self_signed', true);
        stream_context_set_option($context, 'ssl', 'verify_peer', false);

        return $context;
    }

    /**
     * Остановка сервера
     */
    public function stop() {
        $pid = @file_get_contents($this->config['pid']);
        if ($pid) {
            posix_kill($pid, SIGTERM);
            for ($i = 0; $i = 10; $i++) {
                sleep(1);

                if (!posix_getpgid($pid)) {
                    unlink($this->config['pid']);

                    return;
                }
            }

            die("Don't stopped" . PHP_EOL);
        }
        else {
            die("Already stopped" . PHP_EOL);
        }
    }

    /**
     * Перезапуск сервера
     */
    public function restart() {
        $pid = @file_get_contents($this->config['pid']);
        if ($pid) {
            $this->stop();
        }

        $this->start();
    }
}