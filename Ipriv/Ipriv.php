<?php

declare(strict_types=1);

namespace App\Ipriv;

use FFI;
use FFI\CData;

final class Ipriv
{
    private const ENGINE = 0;

    private static $ffi = null;

    public function __construct(
        string $libraryPath,
        private string $secretKey,
        private string $publicKey,
        private string $password,
        private string $serial
    ) {
        if (null === self::$ffi) {
            self::$ffi = FFI::cdef('
                typedef struct
                {
                 short eng;
                 short type;
                 unsigned long keyserial;
                 char userid[24];
                 void* key;
                 unsigned int flags;
                 unsigned long timestamp;
                } IPRIV_KEY;

                int Crypt_Initialize(void);
                int Crypt_OpenSecretKey(int eng, const char* src, int nsrc, const char* passwd, IPRIV_KEY* key);
                int Crypt_Sign(const char* src, int nsrc, char* dst, int ndst, IPRIV_KEY* key);
                int Crypt_CloseKey(IPRIV_KEY* key);
                int Crypt_Done(void);
                int Crypt_OpenPublicKey(int eng, const char* src, int nsrc, unsigned long keyserial, IPRIV_KEY* key, int cakey);
                int Crypt_Verify(const char* src, int nsrc, int pdst, int pndst, IPRIV_KEY* key);
                int Crypt_Encrypt(const char* src, int nsrc, char* dst, int ndst, IPRIV_KEY* key);
                int Crypt_Decrypt(const char* src, int nsrc, char* dst, int ndst, IPRIV_KEY* key);
        ', $libraryPath);
        }
    }

    /**
     * @throws IprivException
     */
    private function init(): void
    {
        $code = self::$ffi->Crypt_Initialize();
        if (0 !== $code) {
            throw new IprivException('Невозможно инициализировать', $code);
        }
    }

    /**
     * @throws IprivException
     */
    private function openSecret(): CData
    {
        $key = self::$ffi->new('IPRIV_KEY');
        $code = self::$ffi->Crypt_OpenSecretKey(self::ENGINE, $this->secretKey, -1, $this->password, FFI::addr($key));
        if (0 !== $code) {
            throw new IprivException('Невозможно открыть секретный ключ', $code);
        }

        return $key;
    }

    /**
     * @throws IprivException
     */
    private function openPublic(): CData
    {
        $key = self::$ffi->new('IPRIV_KEY');
        $code = self::$ffi->Crypt_OpenPublicKey(0, $this->publicKey, -1, $this->serial, FFI::addr($key), 0);
        if (0 !== $code) {
            throw new IprivException('Невозможно открыть публичный ключ', $code);
        }

        return $key;
    }

    /**
     * @throws IprivException
     */
    private function closeKey(CData $key): void
    {
        $code = self::$ffi->Crypt_CloseKey(FFI::addr($key));
        if (0 !== $code) {
            throw new IprivException('Невозможно закрыть секретный ключ', $code);
        }
    }

    /**
     * @throws IprivException
     */
    private function destroy(): void
    {
        $code = self::$ffi->Crypt_Done();
        if (0 !== $code) {
            throw new IprivException('Невозможно уничтожить объект', $code);
        }
    }

    /**
     * @throws IprivException
     */
    public function sign(string $string): string
    {
        try {
            $this->init();
            $key = $this->openSecret();

            $out = self::$ffi->new('char[2048]');
            $length = self::$ffi->Crypt_Sign($string, -1, $out, 2048, FFI::addr($key));
            if ($length <= 0) {
                throw new IprivException('Не удалось создать подпись', $length);
            }

            $sig = FFI::string($out, $length);

            $this->closeKey($key);
            $this->destroy();

            return $sig;
        } catch (\Throwable $exception) {
            throw new IprivException('Невозможно создать подпись', previous: $exception);
        }
    }

    /**
     * @throws IprivException
     */
    public function verify(string $string): bool
    {
        try {
            $valid = true;

            $this->init();
            $key = $this->openPublic();
            $code = self::$ffi->Crypt_Verify($string, -1, 0, 0, FFI::addr($key));
            if (0 !== $code) {
                $valid = false;
            }
            $this->closeKey($key);
            $this->destroy();

            return $valid;
        } catch (\Throwable $exception) {
            throw new IprivException('Невозможно проверить подпись', previous: $exception);
        }
    }

    /**
     * @throws IprivException
     */
    public function encrypt(string $string): string
    {
        try {
            $this->init();
            $key = $this->openPublic();
            $out = self::$ffi->new('char[2048]');
            $length = self::$ffi->Crypt_Encrypt($string, -1, $out, 2048, FFI::addr($key));
            if ($length <= 0) {
                throw new IprivException('Не удалось зашифровать сообщение', $length);
            }
            $encrypted = FFI::string($out, $length);
            $this->closeKey($key);
            $this->destroy();

            return $encrypted;
        } catch (\Throwable $exception) {
            throw new IprivException('Невозможно зашифровать сообщение', previous: $exception);
        }
    }

    /**
     * @throws IprivException
     */
    public function decrypt(string $string): string
    {
        try {
            $this->init();
            $key = $this->openSecret();
            $out = self::$ffi->new('char[2048]');
            $length = self::$ffi->Crypt_Decrypt($string, -1, $out, 2048, FFI::addr($key));
            if ($length <= 0) {
                throw new IprivException('Не удалось расшифровать сообщение', $length);
            }
            $decrypted = FFI::string($out, $length);
            $this->closeKey($key);
            $this->destroy();

            return $decrypted;
        } catch (\Throwable $exception) {
            throw new IprivException('Невозможно расшифровать сообщение', previous: $exception);
        }
    }
}
