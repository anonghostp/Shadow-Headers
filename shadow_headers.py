#!/usr/bin/env python3
"""
Shadow Headers - verificador de cabeçalhos HTTP de segurança.

Autor : Mr Joker (GNU Modder)
Licença: MIT

Uso ético: usa apenas em sistemas para os quais tens autorização explícita.
"""

import argparse
import json
import sys
import urllib.error
import urllib.request

USER_AGENT = "ShadowHeaders/1.0 (+https://github.com/mrjoker-web)"

# Cabeçalhos de segurança esperados: nome -> (descrição, valor esperado ou None)
CABECALHOS_SEGURANCA = {
    "Strict-Transport-Security": ("Força HTTPS (HSTS)", None),
    "Content-Security-Policy": ("Mitiga XSS e injeção de conteúdo", None),
    "X-Frame-Options": ("Protege contra clickjacking", None),
    "X-Content-Type-Options": ("Impede MIME sniffing", "nosniff"),
    "Referrer-Policy": ("Controla o envio do cabeçalho Referer", None),
    "Permissions-Policy": ("Limita o acesso a APIs do browser", None),
}

# Cabeçalhos que revelam informação sobre o servidor/stack
CABECALHOS_FUGA = {
    "Server": "Revela o software do servidor",
    "X-Powered-By": "Revela a tecnologia da aplicação",
    "X-AspNet-Version": "Revela a versão do ASP.NET",
}

# ---------------------------------------------------------------- aparência

class Cores:
    def __init__(self, ativas):
        self.verde = "\033[92m" if ativas else ""
        self.vermelho = "\033[91m" if ativas else ""
        self.amarelo = "\033[93m" if ativas else ""
        self.ciano = "\033[96m" if ativas else ""
        self.negrito = "\033[1m" if ativas else ""
        self.reset = "\033[0m" if ativas else ""


def banner(cores):
    linhas = [
        "SHADOW HEADERS",
        "by Mr Joker (GNU Modder)",
        "verificador de cabeçalhos HTTP",
    ]
    largura = max(len(l) for l in linhas) + 4
    topo = "╔" + "═" * largura + "╗"
    fundo = "╚" + "═" * largura + "╝"
    corpo = [f"║  {l.ljust(largura - 2)}║" for l in linhas]
    return "\n".join(
        [f"{cores.ciano}{topo}"] + corpo + [f"{fundo}{cores.reset}", ""]
    )

# ---------------------------------------------------------------- lógica

def normalizar_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def obter_cabecalhos(url, timeout):
    """Devolve (estado HTTP, URL final, cabeçalhos em minúsculas)."""
    pedido = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT}, method="GET"
    )
    try:
        with urllib.request.urlopen(pedido, timeout=timeout) as resp:
            cabecalhos = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, resp.geturl(), cabecalhos
    except urllib.error.HTTPError as erro:
        # Respostas 4xx/5xx também trazem cabeçalhos úteis
        cabecalhos = {k.lower(): v for k, v in erro.headers.items()}
        return erro.code, erro.geturl() or url, cabecalhos


def analisar(cabecalhos):
    resultados = []

    for nome, (descricao, esperado) in CABECALHOS_SEGURANCA.items():
        valor = cabecalhos.get(nome.lower())
        if valor is None:
            estado = "em_falta"
        elif esperado and valor.strip().lower() != esperado:
            estado = "valor_invalido"
        else:
            estado = "ok"
        resultados.append({
            "cabecalho": nome,
            "estado": estado,
            "valor": valor,
            "descricao": descricao,
        })

    for nome, descricao in CABECALHOS_FUGA.items():
        valor = cabecalhos.get(nome.lower())
        if valor is not None:
            resultados.append({
                "cabecalho": nome,
                "estado": "fuga",
                "valor": valor,
                "descricao": descricao,
            })

    return resultados


def pontuacao(resultados):
    total = len(CABECALHOS_SEGURANCA)
    ok = sum(1 for r in resultados
             if r["estado"] == "ok" and r["cabecalho"] in CABECALHOS_SEGURANCA)
    return round(ok / total * 100)


def verificar(url, timeout):
    url = normalizar_url(url)
    try:
        estado, final, cabecalhos = obter_cabecalhos(url, timeout)
    except Exception as erro:  # URLError, timeout, SSL, etc.
        return {"url": url, "erro": str(erro)}

    resultados = analisar(cabecalhos)
    return {
        "url": url,
        "url_final": final,
        "http_estado": estado,
        "pontuacao": pontuacao(resultados),
        "resultados": resultados,
    }


def imprimir(rel, cores):
    print(f"{cores.negrito}{rel['url']}{cores.reset}")

    if "erro" in rel:
        print(f"  {cores.vermelho}✘ Erro: {rel['erro']}{cores.reset}\n")
        return

    print(f"  Estado HTTP : {rel['http_estado']}")
    if rel["url_final"] != rel["url"]:
        print(f"  Redirecionado para: {rel['url_final']}")

    simbolos = {
        "ok": (cores.verde, "✔", "OK"),
        "em_falta": (cores.vermelho, "✘", "Em falta"),
        "valor_invalido": (cores.amarelo, "!", "Valor inesperado"),
        "fuga": (cores.amarelo, "!", "Fuga de informação"),
    }

    for r in rel["resultados"]:
        cor, simbolo, rotulo = simbolos[r["estado"]]
        valor = f" = {r['valor']}" if r["valor"] else ""
        print(f"  {cor}{simbolo} {r['cabecalho']:<28}{rotulo}{cores.reset}{valor}")
        print(f"      {cores.ciano}{r['descricao']}{cores.reset}")

    pts = rel["pontuacao"]
    cor = cores.verde if pts >= 80 else cores.amarelo if pts >= 50 else cores.vermelho
    print(f"\n  Pontuação de segurança: {cor}{cores.negrito}{pts}%{cores.reset}\n")

# ---------------------------------------------------------------- main

def main():
    parser = argparse.ArgumentParser(
        description="Shadow Headers - verifica cabeçalhos HTTP de segurança.",
        epilog="Usa apenas em alvos com autorização explícita.",
    )
    parser.add_argument("urls", nargs="+", help="URLs a analisar")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                        help="timeout em segundos (padrão: 10)")
    parser.add_argument("--json", action="store_true",
                        help="saída em JSON")
    parser.add_argument("--no-color", action="store_true",
                        help="desativa cores")
    args = parser.parse_args()

    usar_cores = sys.stdout.isatty() and not args.no_color and not args.json
    cores = Cores(usar_cores)

    relatorios = [verificar(u, args.timeout) for u in args.urls]

    if args.json:
        print(json.dumps(relatorios, ensure_ascii=False, indent=2))
        return 0

    print(banner(cores))
    for rel in relatorios:
        imprimir(rel, cores)
    return 0


if __name__ == "__main__":
    sys.exit(main())
