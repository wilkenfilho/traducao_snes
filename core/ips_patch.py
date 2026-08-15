"""
core.ips_patch
---------------
Implementação do formato IPS clássico (International Patching System):

  "PATCH" (5 bytes) + N x [offset(3B BE) + length(2B BE) + data(length)]
  + "EOF" (3 bytes)

- Um length == 0 indica um registro RLE: [offset(3B) + 0x0000 + count(2B) + byte(1B)].
  Não usamos RLE na geração (para manter o diff 100% explícito e auditável),
  mas apply_ips() sabe interpretar RLE de patches externos.
- Offset máximo suportado pelo formato: 0xFFFFFF (16 MB - 1), suficiente
  para qualquer ROM SNES padrão (até 8MB / ExHiROM até ~6MB úteis).
- O offset literal 0x454F46 ("EOF" em ASCII) nunca pode aparecer como
  início de registro, pois seria confundido com o marcador de fim de
  arquivo. Detectamos e evitamos esse caso automaticamente.
"""

from __future__ import annotations
from dataclasses import dataclass

MAGIC = b"PATCH"
EOF_MARKER = b"EOF"
EOF_AS_INT = int.from_bytes(EOF_MARKER, "big")
MAX_OFFSET = 0xFFFFFF
MAX_CHUNK = 0xFFFF - 1  # evita colidir com marcador RLE (length==0)


@dataclass
class IpsValidationResult:
    ok: bool
    message: str
    record_count: int = 0
    total_bytes_changed: int = 0


def _diff_ranges(original: bytes, modified: bytes):
    """Gera tuplas (start, end_exclusive) de regiões que diferem."""
    max_len = max(len(original), len(modified))
    i = 0
    while i < max_len:
        ob = original[i] if i < len(original) else None
        mb = modified[i] if i < len(modified) else None
        if ob != mb:
            j = i
            gap = 0
            while j < max_len:
                ob2 = original[j] if j < len(original) else None
                mb2 = modified[j] if j < len(modified) else None
                if ob2 == mb2:
                    gap += 1
                    if gap > 6:  # tolera pequenos trechos idênticos dentro do mesmo bloco de mudança
                        j -= gap - 1
                        break
                else:
                    gap = 0
                j += 1
            yield (i, min(j, max_len))
            i = min(j, max_len)
        else:
            i += 1


def create_ips(original: bytes, modified: bytes, offset_shift: int = 0) -> bytes:
    """
    Cria um patch IPS contendo apenas as diferenças entre `original` e
    `modified`. `offset_shift` permite gerar o patch já ajustado para uma
    ROM com header de 512 bytes (offset_shift=512), mantendo os dados
    internos idênticos aos calculados sobre a ROM sem header.
    """
    out = bytearray()
    out += MAGIC

    for start, end in _diff_ranges(original, modified):
        pos = start
        while pos < end:
            chunk_end = min(pos + MAX_CHUNK, end)
            chunk = modified[pos:chunk_end] if chunk_end <= len(modified) else modified[pos:]
            length = len(chunk)
            if length == 0:
                pos = chunk_end
                continue
            real_offset = pos + offset_shift
            if real_offset > MAX_OFFSET:
                raise ValueError(
                    f"Offset {real_offset:#x} excede o limite do formato IPS (16MB). "
                    "ROM incompatível com IPS clássico; considere BPS."
                )
            if real_offset == EOF_AS_INT:
                real_offset -= 1
                pos -= 1
                chunk = modified[pos:pos + length]
            out += real_offset.to_bytes(3, "big")
            out += length.to_bytes(2, "big")
            out += chunk
            pos = chunk_end

    out += EOF_MARKER
    return bytes(out)


def apply_ips(original: bytes, patch: bytes) -> bytes:
    if patch[:5] != MAGIC:
        raise ValueError("Arquivo não é um patch IPS válido (assinatura PATCH ausente).")
    result = bytearray(original)
    i = 5
    while i < len(patch):
        if patch[i:i + 3] == EOF_MARKER and i + 3 >= len(patch) - 3:
            # pode ser o marcador final; mas só confirmamos ao consumir todo o resto
            remaining = patch[i:]
            if remaining == EOF_MARKER:
                break
        offset = int.from_bytes(patch[i:i + 3], "big")
        i += 3
        length = int.from_bytes(patch[i:i + 2], "big")
        i += 2
        if length == 0:
            # registro RLE
            count = int.from_bytes(patch[i:i + 2], "big")
            i += 2
            value = patch[i]
            i += 1
            if offset + count > len(result):
                result.extend(b"\x00" * (offset + count - len(result)))
            for k in range(count):
                result[offset + k] = value
        else:
            data = patch[i:i + length]
            i += length
            if offset + length > len(result):
                result.extend(b"\x00" * (offset + length - len(result)))
            result[offset:offset + length] = data
    return bytes(result)


def validate_round_trip(original: bytes, modified: bytes, patch: bytes) -> IpsValidationResult:
    """
    Garante que original + patch reconstrói exatamente `modified`.
    Esta função é a última linha de defesa: se falhar, o patch NUNCA deve
    ser entregue ao usuário.
    """
    try:
        rebuilt = apply_ips(original, patch)
    except Exception as e:  # noqa: BLE001
        return IpsValidationResult(ok=False, message=f"Falha ao reaplicar o patch para validação: {e}")

    if len(rebuilt) != len(modified):
        return IpsValidationResult(
            ok=False,
            message=f"Tamanho reconstruído ({len(rebuilt)}) difere do esperado ({len(modified)})."
        )
    if rebuilt != modified:
        diffs = sum(1 for a, b in zip(rebuilt, modified) if a != b)
        return IpsValidationResult(
            ok=False,
            message=f"ROM reconstruída não é idêntica à ROM traduzida ({diffs} bytes divergentes)."
        )

    count = 0
    total_changed = 0
    i = 5
    while i < len(patch) - 3 or (i < len(patch) and patch[i:] != EOF_MARKER):
        if patch[i:i + 3] == EOF_MARKER and patch[i:] == EOF_MARKER:
            break
        i += 3
        length = int.from_bytes(patch[i:i + 2], "big")
        i += 2
        if length == 0:
            i += 3
            count += 1
        else:
            i += length
            count += 1
            total_changed += length
        if i >= len(patch):
            break

    return IpsValidationResult(
        ok=True,
        message="Validação de round-trip (original + IPS == ROM traduzida) bem-sucedida.",
        record_count=count,
        total_bytes_changed=total_changed,
    )
