"""
Análise Estatística via Bootstrap
Artigo: Detecção de Vulnerabilidades em Smart Contracts com LLMs
Autores: Felipe Mello Fonseca, Pedro Henrique Gonzalez, Diogo Silveira Mendonça

Reproduz os valores da Tabela 3 (F1-score com IC95%) do artigo.
Semente aleatória fixada em 42 para reprodutibilidade.

Requisitos:
    pip install pandas numpy openpyxl

Estrutura esperada dos arquivos:
    - gemini_TP.xlsx  : planilha de verdadeiros positivos do Gemini
    - gemini_FP.xlsx  : planilha de falsos positivos do Gemini
    - gpt4_TP.xlsx    : planilha de verdadeiros positivos do GPT-4
    - gpt4_FP.xlsx    : planilha de falsos positivos do GPT-4
    - gabarito.csv    : gabarito com colunas [Arquivo, Vulnerabilidade, Linha]

    Todas disponíveis em:
    https://github.com/drinith/FONSECA_DVCIEFA_LLMs/tree/master/manual_analysis
"""

import pandas as pd
import numpy as np
import openpyxl

# ── Configuração ──────────────────────────────────────────────────────────────
np.random.seed(42)
N_BOOTSTRAP = 10000

VULNS = [
    'REENTRANCY', 'ACCESS_CONTROL', 'ARITHMETIC', 'UNCHECKED_LL_CALLS',
    'DENIAL_OF_SERVICE', 'BAD_RANDOMNESS', 'FRONT_RUNNING',
    'TIME_MANIPULATION', 'SHORT_ADDRESSES'
]

# Caminhos dos arquivos — ajuste se necessário
PATH_GEMINI_TP = 'gemini_TP.xlsx'
PATH_GEMINI_FP = 'gemini_FP.xlsx'
PATH_GPT4_TP   = 'gpt4_TP.xlsx'
PATH_GPT4_FP   = 'gpt4_FP.xlsx'
PATH_GABARITO  = 'gabarito.csv'

# ── Funções auxiliares ────────────────────────────────────────────────────────
def load_sheet(path):
    """Carrega planilha xlsx como DataFrame."""
    wb = openpyxl.load_workbook(path, read_only=True)
    ws = wb.active
    rows = list(ws.iter_rows(values_only=True))
    return pd.DataFrame(rows[1:], columns=rows[0])


def get_totals(df_tp, df_fp, vulns):
    """Soma TPs e FPs por categoria de vulnerabilidade."""
    totals = {}
    for v in vulns:
        tp = pd.to_numeric(
            df_tp[v] if v in df_tp.columns else 0, errors='coerce'
        ).fillna(0).sum()
        fp = pd.to_numeric(
            df_fp[v] if v in df_fp.columns else 0, errors='coerce'
        ).fillna(0).sum()
        totals[v] = {'tp': int(tp), 'fp': int(fp)}
    return totals


def bootstrap_f1(tp, fp, gab, n=N_BOOTSTRAP):
    """
    Calcula F1-score central e IC95% via bootstrap não-paramétrico.

    A lógica de recall usa o gabarito real como denominador,
    reproduzindo exatamente a metodologia do script de análise manual
    (Colab). FN = gabarito - TP, sem truncagem.

    Parâmetros
    ----------
    tp  : int   — verdadeiros positivos
    fp  : int   — falsos positivos
    gab : int   — total de ocorrências no gabarito
    n   : int   — número de reamostras bootstrap

    Retorna
    -------
    (media, ic_lower, ic_upper) em percentual (0–100)
    """
    fn = max(gab - tp, 0)  # para montar vetor de amostras
    preds  = np.array([1] * tp + [1] * fp + [0] * fn)
    labels = np.array([1] * tp + [0] * fp + [1] * fn)
    n_s = len(preds)

    f1s = []
    for _ in range(n):
        idx  = np.random.choice(n_s, n_s, replace=True)
        p_b  = preds[idx]
        l_b  = labels[idx]
        tp_b = int(((p_b == 1) & (l_b == 1)).sum())
        fp_b = int(((p_b == 1) & (l_b == 0)).sum())
        prec = tp_b / (tp_b + fp_b) if (tp_b + fp_b) > 0 else 0
        rec  = tp_b / gab           if gab > 0           else 0
        f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
        f1s.append(f1)

    f1s = np.array(f1s)
    return (
        float(np.mean(f1s) * 100),
        float(np.percentile(f1s, 2.5) * 100),
        float(np.percentile(f1s, 97.5) * 100),
    )


# ── Carregamento dos dados ────────────────────────────────────────────────────
df_gab = pd.read_csv(PATH_GABARITO)
df_gab['Vulnerabilidade'] = (
    df_gab['Vulnerabilidade'].str.strip().str.replace(' ', '_').str.upper()
)
gabarito = {v: len(df_gab[df_gab['Vulnerabilidade'] == v]) for v in VULNS}

gemini_totals = get_totals(
    load_sheet(PATH_GEMINI_TP), load_sheet(PATH_GEMINI_FP), VULNS
)
gpt4_totals = get_totals(
    load_sheet(PATH_GPT4_TP), load_sheet(PATH_GPT4_FP), VULNS
)

# ── Cálculo e exibição ────────────────────────────────────────────────────────
print(f"\n{'Bootstrap não-paramétrico — ' + str(N_BOOTSTRAP) + ' reamostras (seed=42)'}")
print("=" * 75)
print(f"{'Vulnerabilidade':<22} {'Modelo':<8} {'F1%':>6}  {'IC95% inferior':>14}  {'IC95% superior':>14}")
print("-" * 75)

for v in VULNS:
    gab = gabarito[v]
    for modelo, totals in [('Gemini', gemini_totals), ('GPT-4', gpt4_totals)]:
        tp = totals[v]['tp']
        fp = totals[v]['fp']
        m, lo, hi = bootstrap_f1(tp, fp, gab)
        print(f"{v:<22} {modelo:<8} {m:>6.1f}  {lo:>14.1f}  {hi:>14.1f}")
    print()