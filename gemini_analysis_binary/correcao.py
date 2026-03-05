import pandas as pd
import os

# ==========================================================
# CONFIGURAÇÃO DE DIRETÓRIOS
DIR_GABARITO = r'./' 
DIR_LOGS     = r'./20250619results_count_gemini_2.0'     
# ==========================================================

def processar_analise_completa():
    gabarito_path = os.path.join(DIR_GABARITO, 'gabarito_vulnerabilidades.csv')
    
    if not os.path.exists(gabarito_path):
        print(f"Erro: Gabarito não encontrado em {gabarito_path}")
        return

    df_gabarito = pd.read_csv(gabarito_path)
    df_gabarito['Arquivo'] = df_gabarito['Arquivo'].str.strip()
    df_gabarito['Vulnerabilidade'] = df_gabarito['Vulnerabilidade'].str.strip()
    
    gabarito_set = set(zip(df_gabarito['Arquivo'], df_gabarito['Vulnerabilidade']))

    mapeamento = {
        'Reentrancy': 'REENTRANCY',
        'Access Control': 'ACCESS_CONTROL',
        'Arithmetic Issues': 'ARITHMETIC',
        'Unchecked Return Values For Low Level Calls': 'UNCHECKED_LL_CALLS',
        'Denial of Service': 'DENIAL_OF_SERVICE',
        'Bad Randomness': 'BAD_RANDOMNESS',
        'Front-Running': 'FRONT_RUNNING',
        'Time Manipulation': 'TIME_MANIPULATION',
        'Short Address Attack': 'SHORT_ADDRESSES'
    }

    tp_results = []
    fp_results = []

    arquivos_log = [f for f in os.listdir(DIR_LOGS) if f.endswith('.txt')]
    
    for arquivo in arquivos_log:
        nome_sol = arquivo.replace('.txt', '.sol')
        caminho_log = os.path.join(DIR_LOGS, arquivo)
        
        dados_tp = {'Arquivo': nome_sol}
        dados_fp = {'Arquivo': nome_sol}
        
        tem_tp = False
        tem_fp = False

        with open(caminho_log, 'r', encoding='utf-8') as f:
            for linha in f:
                if ':' in linha:
                    partes = linha.split(':')
                    if len(partes) < 2 or not partes[1].strip(): continue
                    
                    vuln_ferramenta = partes[0].strip()
                    try:
                        valor = int(partes[1].strip())
                    except: continue

                    vuln_padrao = mapeamento.get(vuln_ferramenta, vuln_ferramenta)
                    
                    if valor > 0:
                        if (nome_sol, vuln_padrao) in gabarito_set:
                            dados_tp[vuln_padrao] = valor
                            tem_tp = True
                        else:
                            dados_fp[vuln_padrao] = valor
                            tem_fp = True

        if tem_tp: tp_results.append(dados_tp)
        if tem_fp: fp_results.append(dados_fp)

    # --- PARTE ALTERADA PARA REMOVER O .0 ---
    
    # Processa TP
    if tp_results:
        df_tp = pd.DataFrame(tp_results).fillna(0)
        # Converte todas as colunas (exceto 'Arquivo') para inteiro
        cols = [c for c in df_tp.columns if c != 'Arquivo']
        df_tp[cols] = df_tp[cols].astype(int)
        df_tp.to_csv('Planilha_Verdadeiros_Positivos.csv', index=False)

    # Processa FP
    if fp_results:
        df_fp = pd.DataFrame(fp_results).fillna(0)
        # Converte todas as colunas (exceto 'Arquivo') para inteiro
        cols = [c for c in df_fp.columns if c != 'Arquivo']
        df_fp[cols] = df_fp[cols].astype(int)
        df_fp.to_csv('Planilha_Falsos_Positivos.csv', index=False)
    
    print(f"Processamento Finalizado!")

if __name__ == "__main__":
    processar_analise_completa()