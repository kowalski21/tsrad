/**
 * dictionary.ts — RADIUS attribute dictionary
 *
 * Port of pyrad/dictionary.py
 *
 * Parses FreeRADIUS-format dictionary files and stores attribute definitions
 * including vendors, types, values, and sub-attributes (TLV).
 *
 * Extended: vendor format support, extended attributes (RFC 6929), caching.
 */

import * as crypto from 'node:crypto';
import { BiDict } from './bidict.js';
import { DictFile } from './dictfile.js';
import { encodeAttr, type RadiusDataType } from './tools.js';

export const DATATYPES = new Set<RadiusDataType>([
  'string', 'ipaddr', 'integer', 'date', 'octets',
  'abinary', 'ipv6addr', 'ipv6prefix', 'short', 'byte',
  'signed', 'ifid', 'ether', 'tlv', 'integer64',
]);

export class ParseError extends Error {
  file: string;
  line: number;

  constructor(msg: string, opts?: { file?: string; line?: number }) {
    const prefix = [opts?.file, opts?.line !== undefined ? `(${opts.line})` : '']
      .filter(Boolean).join('');
    super(prefix ? `${prefix}: Parse error: ${msg}` : `Parse error: ${msg}`);
    this.name = 'ParseError';
    this.file = opts?.file ?? '';
    this.line = opts?.line ?? -1;
  }
}

/** Vendor-specific type/length field sizes for VSA encoding/decoding. */
export interface VendorFormat {
  typeSize: 1 | 2 | 4;
  lengthSize: 0 | 1 | 2;
}

export class Attribute {
  name: string;
  code: number;
  type: RadiusDataType;
  vendor: string;
  encrypt: number;
  hasTag: boolean;
  values: BiDict<string, Buffer>;
  subAttributes: Map<number, string>;
  parent: Attribute | null;
  isSubAttribute: boolean;
  /** RFC 6929 extended attribute flag */
  extended: boolean;
  /** Extended attribute type (241-244) */
  extendedType: number;
  /** Extended attribute sub-code within the extended space */
  extendedCode: number;

  constructor(
    name: string,
    code: number,
    datatype: RadiusDataType,
    opts?: {
      isSubAttribute?: boolean;
      vendor?: string;
      values?: Record<string, Buffer>;
      encrypt?: number;
      hasTag?: boolean;
      extended?: boolean;
      extendedType?: number;
      extendedCode?: number;
    },
  ) {
    if (!DATATYPES.has(datatype)) throw new Error('Invalid data type: ' + datatype);
    this.name = name;
    this.code = code;
    this.type = datatype;
    this.vendor = opts?.vendor ?? '';
    this.encrypt = opts?.encrypt ?? 0;
    this.hasTag = opts?.hasTag ?? false;
    this.values = new BiDict<string, Buffer>();
    this.subAttributes = new Map<number, string>();
    this.parent = null;
    this.isSubAttribute = opts?.isSubAttribute ?? false;
    this.extended = opts?.extended ?? false;
    this.extendedType = opts?.extendedType ?? 0;
    this.extendedCode = opts?.extendedCode ?? 0;

    if (opts?.values) {
      for (const [key, value] of Object.entries(opts.values)) {
        this.values.add(key, value);
      }
    }
  }
}

/** Key type used in attrindex: number for standard, tuple for vendor or sub-attributes */
export type AttrKey = number | [number, number] | [number, number, number];

export class Dictionary {
  vendors: BiDict<string, number>;
  attrindex: BiDict<string, AttrKey>;
  attributes: Map<string, Attribute>;
  /** Vendor format specifications: vendorId → { typeSize, lengthSize } */
  vendorFormats: Map<number, VendorFormat>;
  private deferParse: Array<{ state: ParserState; tokens: string[] }>;
  /** Source files used in the most recent readDictionary calls (for cache invalidation) */
  private sourceFiles: string[] = [];

  constructor(...dicts: string[]) {
    this.vendors = new BiDict<string, number>();
    this.vendors.add('', 0);
    this.attrindex = new BiDict<string, AttrKey>();
    this.attributes = new Map<string, Attribute>();
    this.vendorFormats = new Map<number, VendorFormat>();
    this.deferParse = [];

    for (const dict of dicts) {
      this.sourceFiles.push(dict);
      this.readDictionary(dict);
    }
  }

  get(key: string): Attribute | undefined {
    return this.attributes.get(key);
  }

  has(key: string): boolean {
    return this.attributes.has(key);
  }

  /** Get vendor format, defaulting to standard {1,1} */
  getVendorFormat(vendorId: number): VendorFormat {
    return this.vendorFormats.get(vendorId) ?? { typeSize: 1, lengthSize: 1 };
  }

  readDictionary(file: string): void {
    const fil = new DictFile(file);
    const state: ParserState = { vendor: '', tlvs: new Map(), file: '', line: 0 };
    this.deferParse = [];

    for (const line of fil) {
      state.file = fil.file;
      state.line = fil.line;
      const stripped = line.split('#')[0].trim();
      const tokens = stripped.split(/\s+/);
      if (tokens.length === 0 || tokens[0] === '') continue;

      const key = tokens[0].toUpperCase();
      switch (key) {
        case 'ATTRIBUTE':
          this.parseAttribute(state, tokens);
          break;
        case 'VALUE':
          this.parseValue(state, tokens, true);
          break;
        case 'VENDOR':
          this.parseVendor(state, tokens);
          break;
        case 'BEGIN-VENDOR':
          this.parseBeginVendor(state, tokens);
          break;
        case 'END-VENDOR':
          this.parseEndVendor(state, tokens);
          break;
      }
    }

    // Process deferred VALUE entries
    for (const { state: s, tokens: t } of this.deferParse) {
      if (t[0].toUpperCase() === 'VALUE') {
        this.parseValue(s, t, false);
      }
    }
    this.deferParse = [];
  }

  // ---- Serialization / Caching ----

  /** Serialize dictionary to a JSON buffer for caching. */
  serialize(): Buffer {
    const data: SerializedDictionary = {
      vendors: [] as Array<[string, number]>,
      vendorFormats: [] as Array<[number, VendorFormat]>,
      attributes: [] as SerializedAttribute[],
      attrindex: [] as Array<[string, AttrKey]>,
      sourceHash: this.computeSourceHash(),
    };

    for (const k of this.vendors.forwardKeys()) {
      data.vendors.push([k, this.vendors.getForward(k)]);
    }

    for (const [id, fmt] of this.vendorFormats) {
      data.vendorFormats.push([id, fmt]);
    }

    for (const [name, attr] of this.attributes) {
      const values: Array<[string, string]> = [];
      for (const k of attr.values.forwardKeys()) {
        values.push([k, attr.values.getForward(k).toString('hex')]);
      }
      const subAttrs = Array.from(attr.subAttributes.entries());
      data.attributes.push({
        name: attr.name,
        code: attr.code,
        type: attr.type,
        vendor: attr.vendor,
        encrypt: attr.encrypt,
        hasTag: attr.hasTag,
        isSubAttribute: attr.isSubAttribute,
        extended: attr.extended,
        extendedType: attr.extendedType,
        extendedCode: attr.extendedCode,
        parentName: attr.parent?.name ?? null,
        values,
        subAttributes: subAttrs,
      });
    }

    for (const k of this.attrindex.forwardKeys()) {
      data.attrindex.push([k, this.attrindex.getForward(k)]);
    }

    return Buffer.from(JSON.stringify(data), 'utf-8');
  }

  /** Restore a dictionary from a serialized cache buffer. */
  static fromCache(buf: Buffer, sourceFiles?: string[]): Dictionary {
    const data: SerializedDictionary = JSON.parse(buf.toString('utf-8'));
    const dict = new Dictionary(); // empty

    // If source files provided, validate hash
    if (sourceFiles && sourceFiles.length > 0) {
      const hash = Dictionary.computeHashForFiles(sourceFiles);
      if (hash !== data.sourceHash) {
        throw new Error('Dictionary cache is stale (source hash mismatch)');
      }
    }

    for (const [name, id] of data.vendors) {
      if (name !== '') dict.vendors.add(name, id);
    }

    for (const [id, fmt] of data.vendorFormats) {
      dict.vendorFormats.set(id, fmt);
    }

    // First pass: create all attributes
    for (const sa of data.attributes) {
      const attr = new Attribute(sa.name, sa.code, sa.type as RadiusDataType, {
        vendor: sa.vendor,
        encrypt: sa.encrypt,
        hasTag: sa.hasTag,
        isSubAttribute: sa.isSubAttribute,
        extended: sa.extended,
        extendedType: sa.extendedType,
        extendedCode: sa.extendedCode,
      });
      for (const [vk, vhex] of sa.values) {
        attr.values.add(vk, Buffer.from(vhex, 'hex'));
      }
      for (const [subCode, subName] of sa.subAttributes) {
        attr.subAttributes.set(subCode, subName);
      }
      dict.attributes.set(sa.name, attr);
    }

    // Second pass: link parents
    for (const sa of data.attributes) {
      if (sa.parentName) {
        const attr = dict.attributes.get(sa.name)!;
        attr.parent = dict.attributes.get(sa.parentName) ?? null;
      }
    }

    for (const [name, key] of data.attrindex) {
      dict.attrindex.add(name, key);
    }

    return dict;
  }

  private computeSourceHash(): string {
    return Dictionary.computeHashForFiles(this.sourceFiles);
  }

  private static computeHashForFiles(files: string[]): string {
    const hash = crypto.createHash('sha256');
    for (const f of files) {
      try {
        const fs = require('node:fs');
        hash.update(fs.readFileSync(f));
      } catch {
        hash.update(f);
      }
    }
    return hash.digest('hex');
  }

  // ---- Parsing ----

  private parseAttribute(state: ParserState, tokens: string[]): void {
    if (tokens.length < 4 || tokens.length > 5) {
      throw new ParseError('Incorrect number of tokens for attribute definition',
        { file: state.file, line: state.line });
    }

    let vendor = state.vendor;
    let hasTag = false;
    let encrypt = 0;

    if (tokens.length >= 5) {
      const options = tokens[4].split(',').map(o => {
        const kv = o.split('=');
        return { key: kv[0], val: kv[1] ?? null };
      });

      for (const { key, val } of options) {
        if (key === 'has_tag') {
          hasTag = true;
        } else if (key === 'encrypt') {
          if (!val || !['1', '2', '3'].includes(val)) {
            throw new ParseError('Illegal attribute encryption: ' + val,
              { file: state.file, line: state.line });
          }
          encrypt = parseInt(val, 10);
        }
      }

      if (!hasTag && encrypt === 0) {
        vendor = tokens[4];
        if (!this.vendors.hasForward(vendor)) {
          if (vendor === 'concat') return; // freeradius compat
          throw new ParseError('Unknown vendor ' + vendor,
            { file: state.file, line: state.line });
        }
      }
    }

    const [, attribute, codeStr, datatypeRaw] = tokens;
    const datatype = datatypeRaw.split('[')[0] as RadiusDataType;

    if (!DATATYPES.has(datatype)) {
      throw new ParseError('Illegal type: ' + datatype,
        { file: state.file, line: state.line });
    }

    // Parse code (may be dotted for sub-attributes or extended: "241.1", "1.2")
    const codesParts = codeStr.split('.').map(c => {
      if (c.startsWith('0x')) return parseInt(c.slice(2), 16);
      if (c.startsWith('0o')) return parseInt(c.slice(2), 8);
      return parseInt(c, 10);
    });

    // Check for RFC 6929 extended attributes (241-244.x)
    const isExtended = codesParts.length === 2 && codesParts[0] >= 241 && codesParts[0] <= 244;

    const isSubAttribute = codesParts.length > 1 && !isExtended;
    let code: number;
    let parentCode: number | null = null;
    let extendedType = 0;
    let extendedCode = 0;

    if (isExtended) {
      extendedType = codesParts[0];
      extendedCode = codesParts[1];
      code = extendedCode; // use sub-code as the code
    } else if (codesParts.length === 2) {
      parentCode = codesParts[0];
      code = codesParts[1];
    } else if (codesParts.length === 1) {
      code = codesParts[0];
    } else {
      throw new ParseError('Nested TLVs are not supported');
    }

    // Build the index key
    let indexKey: AttrKey;
    if (isExtended) {
      // Store extended attrs with a unique key: [extendedType, extendedCode]
      indexKey = [extendedType, extendedCode];
    } else if (vendor) {
      const vendorCode = this.vendors.getForward(vendor);
      indexKey = isSubAttribute
        ? [vendorCode, parentCode!, code]
        : [vendorCode, code];
    } else {
      indexKey = isSubAttribute
        ? [parentCode!, code]
        : code;
    }

    this.attrindex.add(attribute, indexKey);
    const attr = new Attribute(attribute, code, datatype, {
      isSubAttribute, vendor, encrypt, hasTag,
      extended: isExtended,
      extendedType,
      extendedCode,
    });
    this.attributes.set(attribute, attr);

    if (datatype === 'tlv') {
      state.tlvs.set(code, attr);
    }

    if (isSubAttribute && parentCode !== null) {
      const parent = state.tlvs.get(parentCode);
      if (parent) {
        parent.subAttributes.set(code, attribute);
        attr.parent = parent;
      }
    }
  }

  private parseValue(state: ParserState, tokens: string[], defer: boolean): void {
    if (tokens.length !== 4) {
      throw new ParseError('Incorrect number of tokens for value definition',
        { file: state.file, line: state.line });
    }

    const [, attrName, key, valueStr] = tokens;
    const adef = this.attributes.get(attrName);
    if (!adef) {
      if (defer) {
        this.deferParse.push({ state: { ...state }, tokens: [...tokens] });
        return;
      }
      throw new ParseError('Value defined for unknown attribute ' + attrName,
        { file: state.file, line: state.line });
    }

    let value: any = valueStr;
    if (['integer', 'signed', 'short', 'byte', 'integer64'].includes(adef.type)) {
      value = valueStr.startsWith('0x')
        ? parseInt(valueStr, 16)
        : valueStr.startsWith('0o')
          ? parseInt(valueStr, 8)
          : parseInt(valueStr, 10);
    }

    const encoded = encodeAttr(adef.type, value);
    adef.values.add(key, encoded);
  }

  private parseVendor(state: ParserState, tokens: string[]): void {
    if (tokens.length < 3 || tokens.length > 4) {
      throw new ParseError('Incorrect number of tokens for vendor definition',
        { file: state.file, line: state.line });
    }

    const vendorName = tokens[1];
    const vendorCode = tokens[2].startsWith('0x')
      ? parseInt(tokens[2], 16)
      : parseInt(tokens[2], 10);

    if (tokens.length === 4) {
      const fmt = tokens[3].split('=');
      if (fmt[0] !== 'format') {
        throw new ParseError("Unknown option '" + fmt[0] + "' for vendor definition",
          { file: state.file, line: state.line });
      }
      const parts = fmt[1].split(',').map(Number);
      if (parts.length !== 2 || ![1, 2, 4].includes(parts[0]) || ![0, 1, 2].includes(parts[1])) {
        throw new ParseError('Unknown vendor format specification ' + fmt[1],
          { file: state.file, line: state.line });
      }
      // Store the vendor format
      this.vendorFormats.set(vendorCode, {
        typeSize: parts[0] as 1 | 2 | 4,
        lengthSize: parts[1] as 0 | 1 | 2,
      });
    }

    this.vendors.add(vendorName, vendorCode);
  }

  private parseBeginVendor(state: ParserState, tokens: string[]): void {
    if (tokens.length !== 2) {
      throw new ParseError('Incorrect number of tokens for begin-vendor statement',
        { file: state.file, line: state.line });
    }
    const vendor = tokens[1];
    if (!this.vendors.hasForward(vendor)) {
      throw new ParseError('Unknown vendor ' + vendor + ' in begin-vendor statement',
        { file: state.file, line: state.line });
    }
    state.vendor = vendor;
  }

  private parseEndVendor(state: ParserState, tokens: string[]): void {
    if (tokens.length !== 2) {
      throw new ParseError('Incorrect number of tokens for end-vendor statement',
        { file: state.file, line: state.line });
    }
    if (state.vendor !== tokens[1]) {
      throw new ParseError('Ending non-open vendor ' + tokens[1],
        { file: state.file, line: state.line });
    }
    state.vendor = '';
  }
}

interface ParserState {
  vendor: string;
  tlvs: Map<number, Attribute>;
  file: string;
  line: number;
}

interface SerializedAttribute {
  name: string;
  code: number;
  type: string;
  vendor: string;
  encrypt: number;
  hasTag: boolean;
  isSubAttribute: boolean;
  extended: boolean;
  extendedType: number;
  extendedCode: number;
  parentName: string | null;
  values: Array<[string, string]>;
  subAttributes: Array<[number, string]>;
}

interface SerializedDictionary {
  vendors: Array<[string, number]>;
  vendorFormats: Array<[number, VendorFormat]>;
  attributes: SerializedAttribute[];
  attrindex: Array<[string, AttrKey]>;
  sourceHash: string;
}
