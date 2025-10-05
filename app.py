# -*- coding: utf-8 -*-
import io
import json
import hashlib
import binascii
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

import pandas as pd
import streamlit as st
from asn1crypto import cms  # Para leer firmas PKCS#7 (.p7s) y extraer messageDigest


# ================== Configuración ==================
st.set_page_config(
    page_title="UD3 — De la prueba jurídica a la prueba criptográfica",
    page_icon="⚖️",
    layout="wide"
)

# Estado para cadena de custodia didáctica
if "chain" not in st.session_state:
    st.session_state.chain: List[Dict[str, Any]] = []


# ================== Utilidades ==================
def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def now_iso_utc() -> str:
    return datetime.now(timezone.utc).isoformat()

def _bytes_to_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode("ascii")

def _hash_linked_entry(prev_hash: Optional[str], payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Construye un bloque simplificado (hash encadenado).
    """
    body = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    base = (prev_hash or "").encode("utf-8") + body
    return {
        "ts_utc": now_iso_utc(),
        "prev": prev_hash or "GENESIS",
        "payload": payload,
        "hash": sha256_hex(base)
    }

def _parse_pkcs7_message_digest(p7s_bytes: bytes) -> Dict[str, Any]:
    """
    Lee un PKCS#7/CMS SignedData (.p7s) y devuelve:
      - algoritmo de digest declarado
      - messageDigest de signedAttrs (hex)
      - si contiene contenido encapsulado
    (No valida cadena ni revocación; es lectura didáctica).
    """
    out: Dict[str, Any] = {}
    ci = cms.ContentInfo.load(p7s_bytes)
    if ci["content_type"].native != "signed_data":
        raise ValueError("El archivo no es SignedData (PKCS#7).")
    sd = ci["content"]
    out["has_encapsulated_content"] = sd["encap_content_info"]["content"] is not None
    # Primer signerInfo
    sis = sd["signer_infos"]
    if len(sis) == 0:
        raise ValueError("No hay signerInfos en el PKCS#7.")
    si = sis[0]
    out["digest_algorithm"] = si["digest_algorithm"]["algorithm"].native  # p. ej. 'sha256'
    # messageDigest en signed_attrs
    signed_attrs = si["signed_attrs"]
    md = None
    if signed_attrs is not None:
        for attr in signed_attrs:
            if attr["type"].dotted == "1.2.840.113549.1.9.4":  # messageDigest
                md = attr["values"][0].native  # bytes
                break
    if md is None:
        raise ValueError("El PKCS#7 no contiene messageDigest en signedAttrs.")
    out["message_digest_hex"] = _bytes_to_hex(md)
    return out


# ================== Contenido didáctico ==================
st.title("UD3 — De la prueba jurídica a la prueba criptográfica")
st.caption("Transición: testimonio/documental/pericial → evidencia matemática · Comparación: documento firmado vs hash autenticado")

tabs = st.tabs([
    "📚 Teoría guiada",
    "🧮 Comparador de valor probatorio",
    "🧰 Simulador de cadena de custodia",
    "✅ Autoevaluación",
    "📦 Glosario & Descargas"
])

# --------- Teoría ---------
with tabs[0]:
    c1, c2 = st.columns([1.2, 1])
    with c1:
        st.subheader("Objetivos de la unidad")
        st.write(
            "- Entender el paso de **prueba testifical/documental/pericial** a **prueba criptográfica** (hash, firma, TSA).\n"
            "- Diferenciar qué aporta un **documento firmado electrónicamente** frente a un **hash autenticado**.\n"
            "- Discutir límites: identidad/capacidad/consentimiento ≠ matemática del hash."
        )

        st.subheader("Mapa rápido de medios de prueba")
        df = pd.DataFrame({
            "Medio de prueba": [
                "Testifical",
                "Documental (pública/privada)",
                "Pericial",
                "Evidencia criptográfica (hash, firma, TSA)"
            ],
            "¿Qué aporta?": [
                "Relato humano bajo contradicción",
                "Constancia escrita; pública: fe pública / privada: valor reforzado si firmada",
                "Criterio técnico objetivo",
                "Integridad/autoría (firma) y/o existencia-en-tiempo (TSA) verificable matemáticamente"
            ],
            "Límites": [
                "Memoria, sesgos",
                "Autenticidad/alteración",
                "Alcance técnico, contradicción",
                "Contexto jurídico (identidad/capacidad), cadena y archivo"
            ]
        })
        st.dataframe(df, width="stretch")

    with c2:
        st.info(
            "La matemática verifica hechos sobre datos. La validez jurídica depende del **contexto probatorio** "
            "(identidad, capacidad, consentimiento, cadena de custodia, conservación, políticas)."
        )

# --------- Comparador de valor probatorio ---------
with tabs[1]:
    st.subheader("Documento firmado electrónicamente ↔ Hash autenticado (con evidencia)")
    st.caption("Comparador didáctico. No sustituye validaciones cualificadas ni políticas corporativas.")

    left, right = st.columns(2)

    with left:
        st.markdown("### A) Documento firmado (PKCS#7 `.p7s` con firma DETACHED)")
        sig_file = st.file_uploader(
            "Sube la firma (.p7s). Si es firma separada, sube también el **documento original** para comprobar el messageDigest.",
            type=["p7s"], key="ud3_sig")
        orig_file = st.file_uploader("Documento original (para comprobar el messageDigest)", type=None, key="ud3_orig")

        if sig_file is not None:
            try:
                sig_bytes = sig_file.read()
                info = _parse_pkcs7_message_digest(sig_bytes)
                st.markdown("**Atributos de la firma (resumen)**")
                st.json(info, expanded=False)

                # Si hay documento, comparar el hash con el messageDigest
                if orig_file is not None:
                    data = orig_file.read()
                    alg = (info.get("digest_algorithm") or "sha256").lower()
                    if alg in ("sha256", "2.16.840.1.101.3.4.2.1"):
                        calc = hashlib.sha256(data).hexdigest()
                    elif alg in ("sha1", "1.3.14.3.2.26"):
                        calc = hashlib.sha1(data).hexdigest()
                    elif alg in ("sha512", "2.16.840.1.101.3.4.2.3"):
                        calc = hashlib.sha512(data).hexdigest()
                    else:
                        calc = hashlib.sha256(data).hexdigest()

                    st.markdown("**Verificación del alcance de la firma (messageDigest)**")
                    st.code(f"messageDigest (PKCS#7): {info['message_digest_hex']}", language="text")
                    st.code(f"Digest del documento: {calc}", language="text")
                    if info["message_digest_hex"].lower() == calc.lower():
                        st.success("✅ El messageDigest coincide: la firma cubre estos datos.")
                    else:
                        st.error("❌ El messageDigest NO coincide con el documento.")

                st.caption(
                    "Nota: aquí NO se valida la cadena de confianza ni el estado de revocación. "
                    "El objetivo es didáctico (alcance de la firma)."
                )
            except Exception as e:
                st.error(f"Error al leer el PKCS#7: {e}")

    with right:
        st.markdown("### B) Hash autenticado (evidencia JSON) + Documento")
        evid_file = st.file_uploader("Evidencia JSON (p. ej., generada en otra práctica)", type=["json"], key="ud3_evid_json")
        doc_file = st.file_uploader("Documento a contrastar con la evidencia", type=None, key="ud3_doc_hash")

        # Comparación hash ↔ documento
        if evid_file is not None and doc_file is not None:
            try:
                evid = json.loads(evid_file.read().decode("utf-8"))
                dbytes = doc_file.read()
                h = sha256_hex(dbytes)
                st.markdown("**Comparación de integridad**")
                st.code(f"SHA-256 (doc): {h}", language="text")
                st.code(f"SHA-256 (evidencia): {evid.get('sha256')}", language="text")
                if h == evid.get("sha256"):
                    st.success("✅ Coincide el hash: integridad preservada respecto a la evidencia.")
                else:
                    st.error("❌ No coincide el hash con la evidencia.")

                st.markdown("**Metadatos de la evidencia**")
                st.json({
                    "filename": evid.get("filename"),
                    "size_bytes": evid.get("size_bytes"),
                    "computed_at_utc": evid.get("computed_at_utc"),
                    "notes": evid.get("notes")
                }, expanded=False)
            except Exception as e:
                st.error(f"No se pudo leer la evidencia: {e}")

    st.divider()
    st.markdown("### Tabla comparativa (resultado pedagógico)")
    comp = pd.DataFrame({
        "Criterio": [
            "Integridad del contenido",
            "Autoría criptográfica",
            "Fecha cierta (datación)",
            "Oponibilidad/fe pública",
            "Verificabilidad independiente",
            "Dependencia de terceros"
        ],
        "Documento firmado (X.509)": [
            "Sí (messageDigest cubierto por la firma)",
            "Sí (clave privada del firmante)",
            "Si hay sello de tiempo o política que la aporte",
            "Depende del contexto (p. ej., cualificada, notarial, etc.)",
            "Sí (herramientas PKI)",
            "CA/PSC y, si aplica, TSA"
        ],
        "Hash autenticado (+ TSA/anchor)": [
            "Sí (hash del fichero)",
            "No por sí solo (no identifica autor)",
            "Sí si incorpora TSA/anchor creíble",
            "No hay fe pública civil por defecto",
            "Sí (recomputando hash y validando TSA)",
            "TSA/red; políticas de evidencia"
        ]
    })
    st.dataframe(comp, width="stretch")

# --------- Simulador de cadena de custodia ---------
with tabs[2]:
    st.subheader("Simulador de cadena de custodia (encadenado con hash)")
    st.caption("Añade eventos (quién, qué, dónde) y genera un **log encadenado** exportable (JSONL).")

    with st.form("custodia_form", clear_on_submit=True):
        actor = st.text_input("Actor (quién)", placeholder="p. ej., Técnico Forense 1")
        accion = st.text_input("Acción (qué)", placeholder="p. ej., Adquisición de imagen forense")
        lugar = st.text_input("Lugar/Soporte (dónde)", placeholder="p. ej., Laboratorio A, Caja #12")
        notas = st.text_area("Notas (opcional)", placeholder="Serie, precintos, hash del soporte, etc.")
        subm = st.form_submit_button("Añadir evento")

    if subm:
        payload = {
            "actor": actor.strip() or "—",
            "accion": accion.strip() or "—",
            "lugar": lugar.strip() or "—",
            "notas": notas.strip() or "—"
        }
        prev = st.session_state.chain[-1]["hash"] if st.session_state.chain else None
        block = _hash_linked_entry(prev, payload)
        st.session_state.chain.append(block)
        st.success("Evento añadido a la cadena.")

    if st.session_state.chain:
        st.markdown("### Vista de la cadena")
        dfc = pd.DataFrame([{
            "ts_utc": e["ts_utc"],
            "prev": e["prev"][:12] + "…" if e["prev"] != "GENESIS" else "GENESIS",
            "hash": e["hash"][:16] + "…",
            "actor": e["payload"]["actor"],
            "accion": e["payload"]["accion"],
            "lugar": e["payload"]["lugar"]
        } for e in st.session_state.chain])
        st.dataframe(dfc, width="stretch")
        st.caption("Hash truncado para lectura; el export incluye hashes completos.")

        colx, coly = st.columns(2)
        with colx:
            if st.button("Verificar consistencia"):
                ok = True
                prev = None
                for e in st.session_state.chain:
                    body = json.dumps(e["payload"], sort_keys=True, ensure_ascii=False).encode("utf-8")
                    base = (prev or "").encode("utf-8") + body
                    if sha256_hex(base) != e["hash"]:
                        ok = False
                        break
                    prev = e["hash"]
                if ok:
                    st.success("✅ Cadena consistente (no hay alteraciones detectables).")
                else:
                    st.error("❌ Inconsistencia detectada (posible alteración).")

        with coly:
            jsonl = "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in st.session_state.chain)
            st.download_button(
                "Exportar cadena (.jsonl)",
                io.BytesIO(jsonl.encode("utf-8")),
                file_name="custodia_ud3.jsonl",
                mime="application/jsonl"
            )
    else:
        st.info("Aún no hay eventos en la cadena. Añade el primero con el formulario.")

# --------- Autoevaluación ---------
with tabs[3]:
    st.subheader("Autoevaluación rápida")
    preguntas = [
        {
            "q": "¿Qué elemento aporta la **autoría criptográfica**?",
            "opts": ["Hash del documento", "Firma electrónica (clave privada del firmante)", "TSA", "Registro público"],
            "ok": "Firma electrónica (clave privada del firmante)"
        },
        {
            "q": "Un hash con TSA cualificada demuestra principalmente…",
            "opts": ["Capacidad del autor", "Existencia e integridad en un momento cierto", "Legalidad del contenido", "Que el documento fue leído por un notario"],
            "ok": "Existencia e integridad en un momento cierto"
        },
        {
            "q": "La cadena de custodia sirve para…",
            "opts": ["Asegurar la confidencialidad del documento", "Demostrar el itinerario y control del objeto probatorio", "Firmar electrónicamente el documento", "Cumplir RGPD automáticamente"],
            "ok": "Demostrar el itinerario y control del objeto probatorio"
        }
    ]
    score = 0
    resp = []
    for i, p in enumerate(preguntas, start=1):
        st.markdown(f"**{i}. {p['q']}**")
        sel = st.radio("Elige una:", p["opts"], key=f"ud3q{i}", index=0)
        resp.append((sel, p["ok"]))
    if st.button("Corregir", key="ud3_corr"):
        for i, (sel, ok) in enumerate(resp, start=1):
            if sel == ok:
                st.success(f"{i}) Correcto ✅")
                score += 1
            else:
                st.error(f"{i}) Incorrecto ❌ → Correcta: {ok}")
        st.info(f"Puntuación: **{score}/{len(preguntas)}**")

# --------- Glosario & Descargas ---------
with tabs[4]:
    st.subheader("Glosario breve")
    glos = pd.DataFrame({
        "Término": [
            "Prueba testifical",
            "Prueba documental",
            "Prueba pericial",
            "Evidencia criptográfica",
            "messageDigest (PKCS#7)",
            "Cadena de custodia"
        ],
        "Definición": [
            "Declaración de testigos bajo contradicción.",
            "Documentos (públicos/privados) con efectos probatorios.",
            "Informe de experto para valorar hechos técnicos.",
            "Prueba matemática (hash, firma, TSA) verificable por terceros.",
            "Huella hash del contenido firmado en el sobre PKCS#7.",
            "Registro trazable de quién tuvo, cómo y cuándo el indicio/soporte."
        ]
    })
    st.dataframe(glos, width="stretch")

    st.caption("Herramienta **docente**: no sustituye validaciones cualificadas, políticas de confianza ni peritajes formales.")
