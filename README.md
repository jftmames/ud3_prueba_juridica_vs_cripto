# UD3 — De la prueba jurídica a la prueba criptográfica (Streamlit)

Aplicación didáctica independiente para la asignatura **Blockchain: fundamentos técnicos y problemática jurídica**.

Incluye:
- Teoría y tabla de medios de prueba
- Comparador de valor probatorio:
  - **A)** Firma electrónica PKCS#7 (.p7s) con comprobación del `messageDigest` contra el documento original
  - **B)** Hash autenticado (JSON de evidencia) generado en otra práctica + verificación del documento
- Simulador de **cadena de custodia** encadenada con hash (JSONL exportable)
- Autoevaluación y glosario

## Ejecutar localmente
1. Python 3.10+
2. `pip install -r requirements.txt`
3. `streamlit run app.py`

## Despliegue web (sin terminal)
- **Streamlit Community Cloud** → New app → sube esta carpeta o conéctala a GitHub → selecciona `app.py` → Deploy.

> Aviso docente: esta herramienta **no** valida cadenas de confianza ni estados de revocación. Es un material pedagógico, no asesoramiento jurídico.
