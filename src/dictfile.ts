/**
 * dictfile.ts — Dictionary file parser with $INCLUDE support
 *
 * Port of pyrad/dictfile.py
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

interface DictNode {
  name: string;
  lines: string[];
  current: number;
  dir: string;
}

export class DictFile implements Iterable<string> {
  private stack: DictNode[] = [];

  constructor(file: string) {
    this.readNode(file);
  }

  /** Create a dictionary from inline text (useful for tests and small services). */
  static fromText(text: string, name = '<inline>'): DictFile {
    const file = new DictFile(name);
    file.stack = [{ name, lines: text.split('\n'), current: 0, dir: process.cwd() }];
    return file;
  }

  private readNode(file: string): void {
    const parentDir = this.curDir();
    let fname: string;
    if (path.isAbsolute(file)) {
      fname = file;
    } else {
      fname = path.join(parentDir, file);
    }

    const content = fs.readFileSync(fname, 'utf-8');
    const lines = content.split('\n');
    const dir = path.dirname(fname);

    this.stack.push({
      name: path.basename(fname),
      lines,
      current: 0,
      dir: path.isAbsolute(dir) ? dir : path.join(parentDir, dir),
    });
  }

  private curDir(): string {
    if (this.stack.length > 0) {
      return this.stack[this.stack.length - 1].dir;
    }
    return process.cwd();
  }

  private getInclude(line: string): string | null {
    const stripped = line.split('#')[0].trim();
    const tokens = stripped.split(/\s+/);
    if (tokens.length > 0 && tokens[0].toUpperCase() === '$INCLUDE') {
      return tokens.slice(1).join(' ');
    }
    return null;
  }

  get line(): number {
    if (this.stack.length > 0) {
      return this.stack[this.stack.length - 1].current;
    }
    return -1;
  }

  get file(): string {
    if (this.stack.length > 0) {
      return this.stack[this.stack.length - 1].name;
    }
    return '';
  }

  [Symbol.iterator](): Iterator<string> {
    return {
      next: (): IteratorResult<string> => {
        while (this.stack.length > 0) {
          const top = this.stack[this.stack.length - 1];
          if (top.current >= top.lines.length) {
            this.stack.pop();
            continue;
          }
          const line = top.lines[top.current];
          top.current++;

          const inc = this.getInclude(line);
          if (inc) {
            try {
              this.readNode(inc);
            } catch {
              // Silently skip missing include files (like pyrad)
            }
            continue;
          }
          return { value: line, done: false };
        }
        return { value: undefined as any, done: true };
      },
    };
  }
}
