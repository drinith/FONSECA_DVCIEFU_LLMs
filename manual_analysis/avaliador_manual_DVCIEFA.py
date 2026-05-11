# -*- coding: utf-8 -*-
"""
Análise Manual — Gemini vs GPT-4
Calcula Precisão, Cobertura e F1 diretamente sobre os dados reais.

Arquivos necessários (mesmo diretório):
    gemini_TP.xlsx, gemini_FP.xlsx, gpt4_TP.xlsx, gpt4_FP.xlsx, gabarito.csv
"""

import pandas as pd
import numpy as np
import openpyxl

VULNS = [
    'REENTRANCY', 'ACCESS_CONTROL', 'ARITHMETIC', 'UNCHECKED_LL_CALLS',
    'DENIAL_OF_SERVICE', 'BAD_RANDOMNESS', 'FRONT_RUNNING',
    'TIME_MANIPULATION', 'SHORT_ADDRESSES'
]

# ── Funções ───────────────────────────────────────────────────────────────────
def load_sheet(path):
    wb = openpyxl.load_workbook(path, read_only=True)
    ws = wb.active
    rows = list(ws.iter_rows(values_only=True))
    return pd.DataFrame(rows[1:], columns=rows[0])


def normalize(name):
    return str(name).replace('.txt', '').replace('.sol', '').strip()


def calcular_metricas(df_tp, df_fp, df_gab_raw, vuln):
    """Calcula TP, FP, FN, Precisão, Cobertura e F1 para uma vulnerabilidade."""
    tp = 0
    if vuln in df_tp.columns:
        tp = pd.to_numeric(df_tp[vuln], errors='coerce').fillna(0).sum()

    fp = 0
    if vuln in df_fp.columns:
        fp = pd.to_numeric(df_fp[vuln], errors='coerce').fillna(0).sum()

    gab = len(df_gab_raw[df_gab_raw['Vulnerabilidade'] == vuln])

    fn = gab - tp
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / gab       if gab > 0        else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return int(tp), int(fp), int(fn), int(gab), precision * 100, recall * 100, f1 * 100


def imprimir_tabela(nome_modelo, resultados):
    print(f"\n--- {nome_modelo} ---")
    print(f"{'Vulnerabilidade':<22} {'TP':>5} {'FP':>5} {'FN':>5} {'Gab':>5}  "
          f"{'Prec(%)':>8} {'Rec(%)':>8} {'F1(%)':>8}")
    print("-" * 75)
    for r in resultados:
        print(f"{r['Vulnerabilidade']:<22} {r['TP']:>5} {r['FP']:>5} {r['FN']:>5} {r['Gabarito']:>5}  "
              f"{r['Precisao']:>8.1f} {r['Cobertura']:>8.1f} {r['F1']:>8.1f}")


# ── Carregamento ──────────────────────────────────────────────────────────────
df_gab_raw = pd.read_csv('gabarito.csv')
df_gab_raw['Vulnerabilidade'] = (
    df_gab_raw['Vulnerabilidade'].str.strip().str.replace(' ', '_').str.upper()
)

gemini_tp = load_sheet('gemini_TP.xlsx')
gemini_fp = load_sheet('gemini_FP.xlsx')
gpt4_tp   = load_sheet('gpt4_TP.xlsx')
gpt4_fp   = load_sheet('gpt4_FP.xlsx')

# ── Cálculo ───────────────────────────────────────────────────────────────────
res_gemini = []
res_gpt4   = []

for v in VULNS:
    tp, fp, fn, gab, prec, rec, f1 = calcular_metricas(gemini_tp, gemini_fp, df_gab_raw, v)
    res_gemini.append({'Vulnerabilidade': v, 'TP': tp, 'FP': fp, 'FN': fn, 'Gabarito': gab,
                       'Precisao': round(prec, 1), 'Cobertura': round(rec, 1), 'F1': round(f1, 1)})

    tp, fp, fn, gab, prec, rec, f1 = calcular_metricas(gpt4_tp, gpt4_fp, df_gab_raw, v)
    res_gpt4.append({'Vulnerabilidade': v, 'TP': tp, 'FP': fp, 'FN': fn, 'Gabarito': gab,
                     'Precisao': round(prec, 1), 'Cobertura': round(rec, 1), 'F1': round(f1, 1)})

# ── Resultado ─────────────────────────────────────────────────────────────────
imprimir_tabela('GEMINI', res_gemini)
imprimir_tabela('GPT-4', res_gpt4)

pd.DataFrame(res_gemini).to_csv('manual_gemini.csv', index=False)
pd.DataFrame(res_gpt4).to_csv('manual_gpt4.csv', index=False)
print("\nSalvos: manual_gemini.csv, manual_gpt4.csv")
