<div align="center">

<img src="mr-joker-banner.png" alt="Mr Joker - banner" width="100%">

# 🛡️ Shadow Headers

**Verificador de cabeçalhos HTTP de segurança**

*by Mr Joker (GNU Modder)*

</div>

---

## ✨ O que faz

Analisa as respostas HTTP de um ou mais sites e indica:

- ✔ quais dos cabeçalhos de segurança estão presentes e com o valor esperado
- ✘ quais estão em falta
- ! cabeçalhos que revelam informação do servidor (`Server`, `X-Powered-By`, `X-AspNet-Version`)
- 📊 uma pontuação de segurança de 0 a 100%

Cabeçalhos verificados:

| Cabeçalhos | Para que servem |
|---|---|
| `Strict-Transport-Security` | Força HTTPS (HSTS) |
| `Content-Security-Policy` | Mitiga XSS e injeção de conteúdo |
| `X-Frame-Options` | Protege contra clickjacking |
| `X-Content-Type-Options` | Impede MIME sniffing (`nosniff`) |
| `Referrer-Policy` | Controla o envio do `Referer` |
| `Permissions-Policy` | Limita o acesso a APIs do browser |

## 📦 Instalação

Não tem dependências externas. Basta ter Python 3.8+.

```bash
git clone https://github.com/mrjoker-web/shadow-headers.git
cd shadow-headers
```

## 🚀 Utilização

```bash
# Um alvo
python3 shadow_headers.py exemplo.com

# Vários alvos
python3 shadow_headers.py exemplo.com https://outro.site

# Timeout personalizado
python3 shadow_headers.py -t 5 exemplo.com

# Saída em JSON (útil para scripts)
python3 shadow_headers.py --json exemplo.com > relatorio.json
```

Se não indicares o protocolo, a ferramenta assume `https://`.

## ⚠️ Uso ético

Esta ferramenta destina-se a auditorias autorizadas, aprendizagem e defesa. Usa-a apenas em sistemas para os quais tens autorização explícita. O autor não se responsabiliza por uso indevido.

## 📄 Licença

Distribuído sob a licença MIT. Ver [LICENSE](LICENSE).

---

<div align="center">

**Shadow Suite** · [github.com/mrjoker-web](https://github.com/mrjoker-web) · Telegram [@mr_joker78](https://t.me/mr_joker78)

</div>
