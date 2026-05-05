"""
Teste de Diferença via Bootstrap — Gemini vs GPT-4
Artigo: Detecção de Vulnerabilidades em Smart Contracts com LLMs
Autores: Felipe Mello Fonseca, Pedro Henrique Gonzalez, Diogo Silveira Mendonça
 
O que este código faz:
    Para cada vulnerabilidade, roda 10.000 reamostras bootstrap PAREADAS
    (os dois modelos recebem EXATAMENTE os mesmos arquivos sorteados em cada
    iteração). Calcula a distribuição da diferença F1(GPT-4) − F1(Gemini) e
    extrai o p-value bilateral e os IC95% de cada modelo.
 
    p-value = proporção de reamostras em que F1(GPT-4) <= F1(Gemini)
    (unilateral: H1 = GPT-4 > Gemini)
 
Requisitos:
    pip install pandas numpy openpyxl
 
Arquivos necessários (mesmo diretório):
    gemini_TP.xlsx, gemini_FP.xlsx, gpt4_TP.xlsx, gpt4_FP.xlsx, gabarito.csv
"""
 
import pandas as pd
import numpy as np
import openpyxl
 
# ── Configuração ──────────────────────────────────────────────────────────────
np.random.seed(42)
N_BOOTSTRAP = 10_000
ALPHA       = 0.05   # nível de significância
 
VULNS = [
    'REENTRANCY', 'ACCESS_CONTROL', 'ARITHMETIC', 'UNCHECKED_LL_CALLS',
    'DENIAL_OF_SERVICE', 'BAD_RANDOMNESS', 'FRONT_RUNNING',
    'TIME_MANIPULATION', 'SHORT_ADDRESSES'
]
 
# ── Funções auxiliares ────────────────────────────────────────────────────────
def load_sheet(path):
    wb = openpyxl.load_workbook(path, read_only=True)
    ws = wb.active
    rows = list(ws.iter_rows(values_only=True))
    return pd.DataFrame(rows[1:], columns=rows[0])
 
 
def normalize(name):
    return str(name).replace('.txt', '').replace('.sol', '').strip()
 
 
def build_per_file(df_tp, df_fp, df_gab_raw, vuln):
    """
    Constrói DataFrame com uma linha por arquivo contendo:
        tp  = verdadeiros positivos detectados nesse arquivo
        fp  = falsos positivos detectados nesse arquivo
        gab = total de ocorrências no gabarito para esse arquivo
    """
    todos = df_tp['Arquivos'].dropna().unique()
 
    tp_map = {}
    if vuln in df_tp.columns:
        for _, row in df_tp.iterrows():
            val = pd.to_numeric(row[vuln], errors='coerce')
            if pd.notna(val) and val > 0:
                k = normalize(row['Arquivos'])
                tp_map[k] = tp_map.get(k, 0) + int(val)
 
    fp_map = {}
    if vuln in df_fp.columns:
        for _, row in df_fp.iterrows():
            val = pd.to_numeric(row[vuln], errors='coerce')
            if pd.notna(val) and val > 0:
                k = normalize(row['Arquivos'])
                fp_map[k] = fp_map.get(k, 0) + int(val)
 
    gab_map = (df_gab_raw[df_gab_raw['Vulnerabilidade'] == vuln]
               .assign(key=lambda d: d['Arquivo'].apply(normalize))
               .groupby('key').size().to_dict())
 
    registros = []
    for arq in todos:
        k = normalize(arq)
        registros.append({
            'arquivo': k,
            'tp':  tp_map.get(k, 0),
            'fp':  fp_map.get(k, 0),
            'gab': gab_map.get(k, 0),
        })
 
    return pd.DataFrame(registros)
 
 
def f1_from_arrays(tp_arr, fp_arr, gab_arr):
    """Calcula F1 a partir de arrays agregados."""
    tp  = tp_arr.sum()
    fp  = fp_arr.sum()
    gab = gab_arr.sum()
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec  = tp / gab       if gab > 0       else 0.0
    return 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
 
 
def bootstrap_paired(df_gemini, df_gpt4, n=N_BOOTSTRAP):
    """
    Bootstrap PAREADO: em cada iteração sorteia-se o MESMO conjunto de
    índices de arquivo para os dois modelos.
 
    Por que pareado?
    ─────────────────
    Queremos medir se GPT-4 É MELHOR QUE Gemini, não se cada um é bom
    isoladamente. Se sorteássemos índices independentes, uma diferença
    observada poderia vir apenas do acaso dos sorteios — não do modelo.
    Com o mesmo sorteio, a única fonte de variação é o desempenho de cada
    modelo naqueles contratos, que é exatamente o que queremos comparar.
 
    Retorna
    ───────
    f1_g  : array (n,) com F1 do Gemini em cada reamostra
    f1_g4 : array (n,) com F1 do GPT-4 em cada reamostra
    """
    # Alinha os DataFrames pelo arquivo (union dos arquivos avaliados)
    todos = sorted(set(df_gemini['arquivo']) | set(df_gpt4['arquivo']))
    idx_map = {a: i for i, a in enumerate(todos)}
    N = len(todos)
 
    def to_arrays(df):
        tp  = np.zeros(N)
        fp  = np.zeros(N)
        gab = np.zeros(N)
        for _, row in df.iterrows():
            i = idx_map.get(row['arquivo'])
            if i is not None:
                tp[i]  = row['tp']
                fp[i]  = row['fp']
                gab[i] = row['gab']
        return tp, fp, gab
 
    tp_g,  fp_g,  gab_g  = to_arrays(df_gemini)
    tp_g4, fp_g4, gab_g4 = to_arrays(df_gpt4)
 
    f1_g  = np.zeros(n)
    f1_g4 = np.zeros(n)
 
    for b in range(n):
        # MESMO sorteio para os dois modelos
        idx = np.random.choice(N, N, replace=True)
 
        f1_g[b]  = f1_from_arrays(tp_g[idx],  fp_g[idx],  gab_g[idx])
        f1_g4[b] = f1_from_arrays(tp_g4[idx], fp_g4[idx], gab_g4[idx])
 
    return f1_g, f1_g4
 
 
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
print(f"\nBootstrap pareado — {N_BOOTSTRAP} reamostras (seed=42)")
print("=" * 90)
print(f"{'Vulnerabilidade':<22} "
      f"{'Gemini F1':>10} {'IC95% Gem':>18}  "
      f"{'GPT-4 F1':>10} {'IC95% GPT4':>18}  "
      f"{'p-val':>7}  {'sig':>4}")
print("-" * 90)
 
resultados = []
 
for v in VULNS:
    df_gem_files = build_per_file(gemini_tp, gemini_fp, df_gab_raw, v)
    df_g4_files  = build_per_file(gpt4_tp,   gpt4_fp,  df_gab_raw, v)
 
    f1_g, f1_g4 = bootstrap_paired(df_gem_files, df_g4_files)
 
    # Métricas resumo
    m_g,  lo_g,  hi_g  = (np.mean(f1_g)*100,
                           np.percentile(f1_g,  2.5)*100,
                           np.percentile(f1_g, 97.5)*100)
    m_g4, lo_g4, hi_g4 = (np.mean(f1_g4)*100,
                           np.percentile(f1_g4,  2.5)*100,
                           np.percentile(f1_g4, 97.5)*100)
 
    # p-value unilateral: H1 = GPT-4 > Gemini
    # "Em quantas reamostras GPT-4 NÃO foi melhor?"
    p_val = float((f1_g4 <= f1_g).mean())
 
    sig = "*" if p_val < ALPHA else ""
 
    print(f"{v:<22} "
          f"{m_g:>10.1f} [{lo_g:>5.1f}; {hi_g:>5.1f}]  "
          f"{m_g4:>10.1f} [{lo_g4:>5.1f}; {hi_g4:>5.1f}]  "
          f"{p_val:>7.3f}  {sig:>4}")
 
    resultados.append({
        'vulnerabilidade': v,
        'f1_gemini': round(m_g, 1),
        'ic95_gem_inf': round(lo_g, 1),
        'ic95_gem_sup': round(hi_g, 1),
        'f1_gpt4': round(m_g4, 1),
        'ic95_g4_inf': round(lo_g4, 1),
        'ic95_g4_sup': round(hi_g4, 1),
        'p_valor': round(p_val, 3),
        'significativo': p_val < ALPHA,
    })
 
print("-" * 90)
print(f"* p < {ALPHA} (H1: GPT-4 > Gemini, unilateral)\n")
 
# ── Exportar CSV ──────────────────────────────────────────────────────────────
df_res = pd.DataFrame(resultados)
df_res.to_csv('bootstrap_resultados_DVCIEFA.csv', index=False)
print("Resultados salvos em: bootstrap_resultados_DVCIEFA.csv")
