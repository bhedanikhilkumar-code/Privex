/**
 * Zero-dependency browser-compatible Buffer shim for @private-protection/core & ml.
 * Implements byteLength, from, concat, readUInt32LE, toString (utf-8, hex, base64).
 */

export class BufferShim extends Uint8Array {
  public static byteLength(string: string, _encoding?: string): number {
    return new TextEncoder().encode(string).length;
  }

  public static override from(
    value: any,
    encodingOrOffset?: any,
    _length?: any
  ): BufferShim {
    if (typeof value === 'string') {
      const encoding = (encodingOrOffset as string) || 'utf-8';
      if (encoding === 'hex') {
        const clean = value.replace(/[^0-9a-fA-F]/g, '');
        const bytes = new Uint8Array(clean.length / 2);
        for (let i = 0; i < bytes.length; i++) {
          bytes[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        }
        return new BufferShim(bytes.buffer as ArrayBuffer, bytes.byteOffset, bytes.byteLength);
      } else if (encoding === 'base64') {
        const binary = atob(value);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
          bytes[i] = binary.charCodeAt(i);
        }
        return new BufferShim(bytes.buffer as ArrayBuffer, bytes.byteOffset, bytes.byteLength);
      } else {
        const bytes = new TextEncoder().encode(value);
        return new BufferShim(bytes.buffer as ArrayBuffer, bytes.byteOffset, bytes.byteLength);
      }
    }

    if (value instanceof Uint8Array) {
      return new BufferShim(value.buffer as ArrayBuffer, value.byteOffset, value.byteLength);
    }

    if (value instanceof ArrayBuffer) {
      return new BufferShim(value, encodingOrOffset as number, _length);
    }

    if (Array.isArray(value)) {
      const bytes = new Uint8Array(value);
      return new BufferShim(bytes.buffer as ArrayBuffer, bytes.byteOffset, bytes.byteLength);
    }

    return new BufferShim(0);
  }

  public static alloc(size: number): BufferShim {
    return new BufferShim(size);
  }

  public static concat(list: Uint8Array[], totalLength?: number): BufferShim {
    const len = totalLength ?? list.reduce((acc, curr) => acc + curr.length, 0);
    const out = new Uint8Array(len);
    let offset = 0;
    for (const item of list) {
      out.set(item, offset);
      offset += item.length;
    }
    return new BufferShim(out.buffer as ArrayBuffer, out.byteOffset, out.byteLength);
  }

  public readUInt32LE(offset = 0): number {
    return (
      (this[offset] |
        (this[offset + 1] << 8) |
        (this[offset + 2] << 16) |
        (this[offset + 3] << 24)) >>>
      0
    );
  }

  public override toString(encoding = 'utf-8'): string {
    if (encoding === 'hex') {
      let hex = '';
      for (let i = 0; i < this.length; i++) {
        hex += this[i].toString(16).padStart(2, '0');
      }
      return hex;
    }
    if (encoding === 'base64') {
      let binary = '';
      for (let i = 0; i < this.length; i++) {
        binary += String.fromCharCode(this[i]);
      }
      return btoa(binary);
    }
    return new TextDecoder('utf-8').decode(this);
  }
}

// Ensure global Buffer is always accessible
if (typeof globalThis !== 'undefined' && !(globalThis as any).Buffer) {
  (globalThis as any).Buffer = BufferShim;
}

export const Buffer = BufferShim;
export default BufferShim;
