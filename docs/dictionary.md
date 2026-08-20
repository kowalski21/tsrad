# Dictionary Guide

The `Dictionary` class parses FreeRADIUS-format dictionary files that define RADIUS attributes, values, and vendors.

## Loading a Dictionary

```ts
import { Dictionary } from '@kowalski21/tsrad';

// Load a single dictionary file
const dict = new Dictionary('/usr/share/freeradius/dictionary');

// Load multiple dictionary files
const dict = new Dictionary(
  '/usr/share/freeradius/dictionary.rfc2865',
  '/usr/share/freeradius/dictionary.rfc2866',
  '/usr/share/freeradius/dictionary.rfc3576',
);
```

Dictionary files can reference other files via `$INCLUDE`:

```
# /etc/freeradius/dictionary
$INCLUDE /usr/share/freeradius/dictionary.rfc2865
$INCLUDE /usr/share/freeradius/dictionary.rfc2866
$INCLUDE dictionary.local
```

Relative paths in `$INCLUDE` resolve from the directory of the including file.

## Dictionary File Format

tsrad supports the FreeRADIUS dictionary file format:

### ATTRIBUTE

```
ATTRIBUTE <name> <code> <type> [options]
```

Types: `string`, `integer`, `ipaddr`, `ipv6addr`, `ipv6prefix`, `date`, `octets`, `abinary`, `signed`, `short`, `byte`, `integer64`, `ifid`, `ether`, `tlv`

Options (comma-separated):
- `has_tag` — attribute supports tagged values (RFC 2868)
- `encrypt=1` — User-Password style encryption (RFC 2865 sec 5.2)
- `encrypt=2` — Tunnel-Password style salt encryption (RFC 2868)
- `encrypt=3` — Ascend-Send-Secret style

Examples:

```
ATTRIBUTE User-Name           1  string
ATTRIBUTE User-Password       2  string    encrypt=1
ATTRIBUTE NAS-IP-Address      4  ipaddr
ATTRIBUTE NAS-Port            5  integer
ATTRIBUTE Framed-IP-Address   8  ipaddr
ATTRIBUTE Session-Timeout    27  integer
ATTRIBUTE Tunnel-Type        64  integer   has_tag
ATTRIBUTE Tunnel-Password    69  string    has_tag,encrypt=2
```

### VALUE

```
VALUE <attribute-name> <value-name> <numeric-value>
```

Maps symbolic names to numeric values for integer attributes:

```
VALUE Service-Type  Login-User     1
VALUE Service-Type  Framed-User    2
VALUE Service-Type  Callback-Login 3

VALUE Acct-Status-Type  Start          1
VALUE Acct-Status-Type  Stop           2
VALUE Acct-Status-Type  Interim-Update 3
```

When these are defined, you can use the symbolic name:

```ts
pkt.addAttribute('Acct-Status-Type', 'Start');
const status = pkt.getAttribute('Acct-Status-Type')[0]; // 'Start'
```

### VENDOR

```
VENDOR <name> <vendor-id> [format=<type-len>,<length-len>]
```

Defines a Vendor-Specific Attribute (VSA) vendor:

```
VENDOR Cisco     9
VENDOR Microsoft 311
VENDOR Mikrotik  14988
```

Format specifies the type and length field sizes in vendor sub-attributes (default `1,1`):

```
VENDOR WiMAX 24757 format=1,1
```

### BEGIN-VENDOR / END-VENDOR

Wraps vendor-specific attributes:

```
VENDOR Mikrotik 14988

BEGIN-VENDOR Mikrotik
ATTRIBUTE Mikrotik-Recv-Limit     1  integer
ATTRIBUTE Mikrotik-Xmit-Limit     2  integer
ATTRIBUTE Mikrotik-Group           3  string
ATTRIBUTE Mikrotik-Wireless-PSK   17  string
ATTRIBUTE Mikrotik-Rate-Limit     8  string
END-VENDOR Mikrotik
```

### Sub-Attributes (TLV)

Dotted notation defines TLV sub-attributes:

```
ATTRIBUTE WiMAX-Capability    1  tlv
ATTRIBUTE WiMAX-Release     1.1  string
ATTRIBUTE WiMAX-Accounting  1.2  integer
```

## Using the Dictionary API

### Check if an attribute exists

```ts
dict.has('User-Name');     // true
dict.has('Nonexistent');   // false
```

### Get attribute definition

```ts
const attr = dict.get('User-Name');
// attr.name    → 'User-Name'
// attr.code    → 1
// attr.type    → 'string'
// attr.vendor  → '' (standard) or 'Mikrotik' etc.
// attr.encrypt → 0 (none), 1, 2, or 3
// attr.hasTag  → false
```

### Attribute class properties

| Property | Type | Description |
|----------|------|-------------|
| `name` | `string` | Attribute name |
| `code` | `number` | Numeric attribute code |
| `type` | `RadiusDataType` | Data type |
| `vendor` | `string` | Vendor name (empty for standard) |
| `encrypt` | `number` | Encryption method (0=none, 1=password, 2=salt, 3=ascend) |
| `hasTag` | `boolean` | Whether the attribute supports tags |
| `values` | `BiDict<string, Buffer>` | Named value mappings |
| `subAttributes` | `Map<number, string>` | TLV sub-attribute map |
| `parent` | `Attribute \| null` | Parent TLV attribute |
| `isSubAttribute` | `boolean` | Whether this is a sub-attribute |

### Look up vendors

```ts
dict.vendors.getForward('Mikrotik');   // 14988 (vendor ID)
dict.vendors.getBackward(14988);       // 'Mikrotik'
dict.vendors.hasForward('Mikrotik');   // true
```

### Look up attribute index

```ts
dict.attrindex.getForward('User-Name');         // 1
dict.attrindex.getForward('Mikrotik-Group');     // [14988, 3]
dict.attrindex.getBackward(1);                   // 'User-Name'
```

## Supported Data Types

| Type | Size | TypeScript Encode | TypeScript Decode |
|------|------|-------------------|-------------------|
| `string` | ≤253 bytes | `string \| Buffer` | `string` |
| `octets` | ≤253 bytes | `string \| Buffer` | `Buffer` |
| `integer` | 4 bytes | `number \| string` | `number` |
| `ipaddr` | 4 bytes | `string` (dotted notation) | `string` |
| `ipv6addr` | 16 bytes | `string` (colon notation) | `string` |
| `ipv6prefix` | 18 bytes | `string` (addr/prefix) | `string` |
| `date` | 4 bytes | `number` (unix timestamp) | `number` |
| `integer64` | 8 bytes | `bigint \| number \| string` | `bigint` |
| `signed` | 4 bytes | `number` | `number` |
| `short` | 2 bytes | `number` | `number` |
| `byte` | 1 byte | `number` | `number` |
| `abinary` | variable | `string` (Ascend filter) | `Buffer` |
| `tlv` | variable | (sub-attributes) | (sub-attributes) |
| `ifid` | — | (as octets) | (as octets) |
| `ether` | — | (as octets) | (as octets) |
