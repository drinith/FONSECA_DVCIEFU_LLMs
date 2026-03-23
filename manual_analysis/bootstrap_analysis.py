"""
Análise Estatística via Bootstrap por Instância Real
Artigo: Detecção de Vulnerabilidades em Smart Contracts com LLMs
Autores: Felipe Mello Fonseca, Pedro Henrique Gonzalez, Diogo Silveira Mendonça

Reproduz os valores da Tabela 3 (F1-score com IC95%) do artigo.
Cada instância corresponde a uma ocorrência real de predição/gabarito
por contrato, preservando a estrutura original dos dados.
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

PATH_GEMINI_TP = 'gemini_TP.xlsx'
PATH_GEMINI_FP = 'gemini_FP.xlsx'
PATH_GPT4_TP   = 'gpt4_TP.xlsx'
PATH_GPT4_FP   = 'gpt4_FP.xlsx'
PATH_GABARITO  = 'gabarito.csv'

# ── Funções auxiliares ────────────────────────────────────────────────────────
def load_sheet(path):
    wb = openpyxl.load_workbook(path, read_only=True)
    ws = wb.active
    rows = list(ws.iter_rows(values_only=True))
    return pd.DataFrame(rows[1:], columns=rows[0])


def build_instances(df_tp, df_fp, df_gab_raw, vuln):
    """
    Constrói vetor de instâncias reais (pred, real) por ocorrência de contrato.

    Cada linha representa uma ocorrência individual:
      - TP: pred=1, real=1  (detecção correta confirmada no gabarito)
      - FP: pred=1, real=0  (detecção indevida, fora do gabarito)
      - FN: pred=0, real=1  (ocorrência do gabarito não detectada)
    """
    instancias = []

    if vuln in df_tp.columns:
        for _, row in df_tp.iterrows():
            val = pd.to_numeric(row[vuln], errors='coerce')
            if pd.notna(val) and val > 0:
                for _ in range(int(val)):
                    instancias.append({'arquivo': row['Arquivos'],
                                       'pred': 1, 'real': 1})

    if vuln in df_fp.columns:
        for _, row in df_fp.iterrows():
            val = pd.to_numeric(row[vuln], errors='coerce')
            if pd.notna(val) and val > 0:
                for _ in range(int(val)):
                    instancias.append({'arquivo': row['Arquivos'],
                                       'pred': 1, 'real': 0})

    tp_por_arquivo = {}
    if vuln in df_tp.columns:
        for _, row in df_tp.iterrows():
            val = pd.to_numeric(row[vuln], errors='coerce')
            if pd.notna(val) and val > 0:
                arq = row['Arquivos']
                tp_por_arquivo[arq] = tp_por_arquivo.get(arq, 0) + int(val)

    gab_por_arquivo = (df_gab_raw[df_gab_raw['Vulnerabilidade'] == vuln]
                       ['Arquivo'].value_counts().to_dict())
    for arquivo, total_gab in gab_por_arquivo.items():
        detectados = tp_por_arquivo.get(arquivo, 0)
        for _ in range(max(total_gab - detectados, 0)):
            instancias.append({'arquivo': arquivo, 'pred': 0, 'real': 1})

    return (pd.DataFrame(instancias) if instancias
            else pd.DataFrame(columns=['arquivo', 'pred', 'real']))


def bootstrap_f1(df_instances, gab_total, n=N_BOOTSTRAP):
    """
    Bootstrap não-paramétrico reamostrado por instância real.

    A cada iteração, reamostram-se as instâncias com reposição e recalculam-se
    precision, recall e F1. O recall usa o gabarito total como denominador,
    consistente com a metodologia de avaliação do artigo.

    Parâmetros
    ----------
    df_instances : DataFrame com colunas pred e real
    gab_total    : total de ocorrências no gabarito para a categoria
    n            : número de reamostras (padrão: 10.000)

    Retorna
    -------
    (media, ic_lower, ic_upper) em percentual (0-100)
    """
    if len(df_instances) == 0:
        return 0.0, 0.0, 0.0

    arr_pred = df_instances['pred'].values
    arr_real = df_instances['real'].values
    n_s = len(arr_pred)

    f1s = []
    for _ in range(n):
        idx  = np.random.choice(n_s, n_s, replace=True)
        p_b  = arr_pred[idx]
        r_b  = arr_real[idx]
        tp_b = int(((p_b == 1) & (r_b == 1)).sum())
        fp_b = int(((p_b == 1) & (r_b == 0)).sum())
        prec = tp_b / (tp_b + fp_b) if (tp_b + fp_b) > 0 else 0
        rec  = tp_b / gab_total     if gab_total > 0      else 0
        f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
        f1s.append(f1)

    f1s = np.array(f1s)
    return (float(np.mean(f1s) * 100),
            float(np.percentile(f1s, 2.5) * 100),
            float(np.percentile(f1s, 97.5) * 100))


# ── Carregamento dos dados ────────────────────────────────────────────────────
df_gab_raw = pd.read_csv(PATH_GABARITO)
df_gab_raw['Vulnerabilidade'] = (
    df_gab_raw['Vulnerabilidade'].str.strip().str.replace(' ', '_').str.upper()
)
gabarito_total = {
    v: len(df_gab_raw[df_gab_raw['Vulnerabilidade'] == v]) for v in VULNS
}

gemini_tp = load_sheet(PATH_GEMINI_TP)
gemini_fp = load_sheet(PATH_GEMINI_FP)
gpt4_tp   = load_sheet(PATH_GPT4_TP)
gpt4_fp   = load_sheet(PATH_GPT4_FP)

# ── Cálculo e exibição ────────────────────────────────────────────────────────
print(f"\nBootstrap por instância real — {N_BOOTSTRAP} reamostras (seed=42)")
print("=" * 70)
print(f"{'Vulnerabilidade':<22} {'Modelo':<8} {'F1%':>6}  "
      f"{'IC95% inf':>9}  {'IC95% sup':>9}  {'n_inst':>6}")
print("-" * 70)

for v in VULNS:
    gab = gabarito_total[v]
    for modelo, tp, fp in [('Gemini', gemini_tp, gemini_fp),
                            ('GPT-4',  gpt4_tp,   gpt4_fp)]:
        df_inst = build_instances(tp, fp, df_gab_raw, v)
        m, lo, hi = bootstrap_f1(df_inst, gab)
        print(f"{v:<22} {modelo:<8} {m:>6.1f}  {lo:>9.1f}  {hi:>9.1f}  "
              f"{len(df_inst):>6}")
    print()
