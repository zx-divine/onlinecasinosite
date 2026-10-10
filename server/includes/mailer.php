<?php
declare(strict_types=1);

/**
 * Fortune Apex SMTP sender.
 * This small dependency-free SMTP transport removes the need to install vendor/ or
 * upload PHPMailer manually. It supports authenticated SMTP over STARTTLS (587)
 * and implicit TLS (465), plus plain SMTP only if a provider explicitly requires it.
 */
function fa_smtp_read($socket, array $expectedCodes): string
{
    $response = '';
    $finalCode = '';
    do {
        $line = fgets($socket, 515);
        if ($line === false) {
            throw new RuntimeException('SMTP connection closed before a complete response.');
        }
        $response .= $line;
        if (strlen($line) < 3 || !ctype_digit(substr($line, 0, 3))) {
            throw new RuntimeException('SMTP server returned an invalid response.');
        }
        $finalCode = substr($line, 0, 3);
        $more = isset($line[3]) && $line[3] === '-';
    } while ($more);

    if (!in_array($finalCode, $expectedCodes, true)) {
        throw new RuntimeException('SMTP server rejected a command (response ' . $finalCode . ').');
    }
    return $response;
}

function fa_smtp_write_all($socket, string $data): void
{
    $length = strlen($data);
    $offset = 0;
    while ($offset < $length) {
        $written = fwrite($socket, substr($data, $offset));
        if ($written === false || $written === 0) {
            throw new RuntimeException('Could not write to the SMTP server.');
        }
        $offset += $written;
    }
}

function fa_smtp_command($socket, string $command, array $expectedCodes): string
{
    if (str_contains($command, "\r") || str_contains($command, "\n")) {
        throw new RuntimeException('Invalid SMTP command.');
    }
    fa_smtp_write_all($socket, $command . "\r\n");
    return fa_smtp_read($socket, $expectedCodes);
}

function fa_email_header_text(string $value): string
{
    return trim(str_replace(["\r", "\n", "\0"], ' ', $value));
}

function fa_encode_header(string $value): string
{
    $value = fa_email_header_text($value);
    if (preg_match('/^[\x20-\x7E]*$/D', $value)) {
        return $value;
    }
    return '=?UTF-8?B?' . base64_encode($value) . '?=';
}

function fa_smtp_b64(string $value): string
{
    return rtrim(chunk_split(base64_encode(str_replace(["\r\n", "\r"], "\n", $value)), 76, "\r\n"));
}

function send_app_mail(array $config, string $to, string $subject, string $body, ?string $htmlBody = null): void
{
    $m = $config['mail'] ?? [];
    $host = trim((string)($m['host'] ?? ''));
    $username = trim((string)($m['username'] ?? ''));
    $password = (string)($m['password'] ?? '');
    $port = (int)($m['port'] ?? 587);
    $encryption = strtolower((string)($m['encryption'] ?? 'tls'));
    $fromEmail = trim((string)($m['from_email'] ?? $username));
    $fromName = (string)($m['from_name'] ?? 'Fortune Apex');

    if ($host === '' || !filter_var($username, FILTER_VALIDATE_EMAIL) || $password === '' ||
        str_contains($password, 'ENTER_NEW_') || str_contains($password, 'REPLACE_WITH') ||
        str_contains($password, 'CHANGE-THIS')) {
        throw new RuntimeException('SMTP is not configured. Run the deployment setup again with a new Google App Password.');
    }
    if (!filter_var($to, FILTER_VALIDATE_EMAIL) || !filter_var($fromEmail, FILTER_VALIDATE_EMAIL)) {
        throw new RuntimeException('SMTP recipient or sender email address is invalid.');
    }
    if (!in_array($encryption, ['tls', 'ssl', 'none'], true) || $port < 1 || $port > 65535) {
        throw new RuntimeException('SMTP transport settings are invalid.');
    }
    if (preg_match('/[\r\n]/', $subject) || preg_match('/[\r\n]/', $fromName)) {
        throw new RuntimeException('Email headers contain invalid characters.');
    }

    $remote = ($encryption === 'ssl' ? 'ssl://' : 'tcp://') . $host . ':' . $port;
    $context = stream_context_create(['ssl' => [
        'verify_peer' => true,
        'verify_peer_name' => true,
        'allow_self_signed' => false,
        'peer_name' => $host,
        'SNI_enabled' => true,
    ]]);
    $errno = 0;
    $errstr = '';
    $socket = @stream_socket_client($remote, $errno, $errstr, 15, STREAM_CLIENT_CONNECT, $context);
    if (!is_resource($socket)) {
        throw new RuntimeException('Could not connect to the configured SMTP host (network/socket error ' . (int)$errno . ').');
    }
    stream_set_timeout($socket, 15);

    try {
        fa_smtp_read($socket, ['220']);
        $domain = (string)(parse_url((string)($config['base_url'] ?? ''), PHP_URL_HOST) ?: 'localhost');
        fa_smtp_command($socket, 'EHLO ' . preg_replace('/[^A-Za-z0-9.-]/', '', $domain), ['250']);

        if ($encryption === 'tls') {
            fa_smtp_command($socket, 'STARTTLS', ['220']);
            $crypto = @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
            if ($crypto !== true) {
                throw new RuntimeException('TLS negotiation with the SMTP provider failed.');
            }
            fa_smtp_command($socket, 'EHLO ' . preg_replace('/[^A-Za-z0-9.-]/', '', $domain), ['250']);
        }

        fa_smtp_command($socket, 'AUTH LOGIN', ['334']);
        fa_smtp_command($socket, base64_encode($username), ['334']);
        fa_smtp_command($socket, base64_encode($password), ['235']);
        fa_smtp_command($socket, 'MAIL FROM:<' . $fromEmail . '>', ['250']);
        fa_smtp_command($socket, 'RCPT TO:<' . $to . '>', ['250', '251', '252']);
        fa_smtp_command($socket, 'DATA', ['354']);

        $headers = [
            'Date: ' . gmdate('D, d M Y H:i:s O'),
            'From: ' . fa_encode_header($fromName) . ' <' . $fromEmail . '>',
            'To: <' . $to . '>',
            'Subject: ' . fa_encode_header($subject),
            'MIME-Version: 1.0',
        ];
        if ($htmlBody === null) {
            $headers[] = 'Content-Type: text/plain; charset=UTF-8';
            $headers[] = 'Content-Transfer-Encoding: base64';
            $messageBody = fa_smtp_b64($body);
        } else {
            $boundary = 'fa_' . bin2hex(random_bytes(16));
            $headers[] = 'Content-Type: multipart/alternative; boundary="' . $boundary . '"';
            $messageBody = '--' . $boundary . "\r\n" .
                "Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" .
                fa_smtp_b64($body) . "\r\n" .
                '--' . $boundary . "\r\n" .
                "Content-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" .
                fa_smtp_b64($htmlBody) . "\r\n" .
                '--' . $boundary . '--';
        }
        $data = implode("\r\n", $headers) . "\r\n\r\n" . $messageBody;
        $data = str_replace(["\r\n", "\r"], "\n", $data);
        $data = str_replace("\n.", "\n..", $data);
        $data = str_replace("\n", "\r\n", $data);
        if (substr($data, -2) !== "\r\n") $data .= "\r\n";
        fa_smtp_write_all($socket, $data . ".\r\n");
        fa_smtp_read($socket, ['250']);
        try { fa_smtp_command($socket, 'QUIT', ['221']); } catch (Throwable $ignored) { /* delivery already accepted */ }
    } finally {
        if (is_resource($socket)) fclose($socket);
    }
}