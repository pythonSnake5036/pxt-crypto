/**
 * Provides cryptography related functions
 */
//% weight=70 icon="\uf185" color=#EC7505
// @ts-ignore
namespace crypto {
    function translate(msg: string): Array<number> {
        let i, charCode, j;
        let bitArray: Array<number> = [];
        for (i = 0; i < msg.length; i++) {
            charCode = msg.charCodeAt(i);
            for (j = 7; j >= 0; j--) {
                bitArray.push((charCode >> j) & 1);
            }
        }
        return bitArray;
    }
    
    let numToHex = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"];
    
    function b2tob16(b2: Array<number>): string {
        let output = "";
    
        for (let i = 0; i < b2.length; i += 4) {
            output += numToHex[parseInt(b2.slice(i, i + 4).join(""), 2)];
        }
    
        return output;
    }
    
    function fillZeros(bits: Array<number>, length=8, endian="LE") {
        let out = bits.slice();
        let l = out.length;
        if (endian == "LE") {
            for (let i = l; i < length; i++) {
                out.push(0)
            }
        } else {
            while (l < length) {
                out.unshift(0);
                l = out.length;
            }
        }
        return out;
    }
    
    function chunker(bits: Array<number>, chunk_length=8): Array<Array<number>> {
        let out: Array<Array<number>> = [];
    
        for (let i = 0; i < bits.length; i += chunk_length) {
            out.push(bits.slice(i, i + chunk_length));
        }
    
        return out;
    }
    
    function initializer(values: Array<number>): Array<Array<number>> {
        // assume 32 bit numbers
        let bin: Array<Array<number>> = [];
    
        let word: Array<number>, i, j;
        for (i = 0; i < values.length; i++) {
            word = [];
            for (j = 31; j >= 0; j--) {
                word.push((values[i] >> j) & 1);
            }
            word = fillZeros(word, 32, "BE");
            bin.push(word);
        }
    
        return bin;
    }
    
    function b10tob2(num: number, bits = 32): string {
        let out = "";
        for (let i = bits - 1; i >= 0; i--) {
            out += (num >> i) & 1;
        }
        return out;
    }
    
    function preprocessMessage(msg: string): Array<Array<number>> {
        let bits = translate(msg);
    
        let length = bits.length;
    
        let bin_l = b10tob2(length);
        let i;
        while (bin_l.length < 64) {
            bin_l = "0" + bin_l;
        }
    
        let messageLength = [];
        for (i = 0; i < 64; i++) {
            messageLength.push(parseInt(bin_l[i]));
        }
    
        if (length < 448) {
            bits.push(1);
            bits = fillZeros(bits, 448, "LE");
            bits = bits.concat(messageLength);
            return [bits];
        } else if (448 <= length && length <= 512) {
            bits.push(1);
            bits = fillZeros(bits, 1024, "LE");
            // replace last 64 bits with message length
            bits = bits.slice(0, -64).concat(messageLength);
            return chunker(bits, 512);
        } else {
            bits.push(1);
            while ((bits.length + 64) % 512 != 0) {
                bits.push(0);
            }
            bits = bits.concat(messageLength);
            return chunker(bits, 512);
        }
    }
    
    function AND(i: Array<number>, j: Array<number>): Array<number> {
        return i.map((x, index) => x && j[index]);
    }
    
    function NOT(i: Array<number>): Array<number> {
        return i.map(x => (!x) ? 1 : 0);
    }
    
    function XOR(i: Array<number>, j: Array<number>): Array<number> {
        return i.map((x, index) => x ^ j[index]);
    }
    
    function xorxor(i: number, j: number, l: number): number {
        return i ^ (j ^ l);
    }
    
    function XORXOR(i: Array<number>, j: Array<number>, l: Array<number>): Array<number> {
        return i.map((x, index) => xorxor(x, j[index], l[index]));
    }
    
    function mode(array: Array<number>): number {
        let modeMap: { [id: number]: number } = {};
        let maxEl: number = array[0], maxCount = 1;
        for (let i = 0; i < array.length; i++) {
            let el = array[i];
            if (modeMap[el] == null)
                modeMap[el] = 1;
            else
                modeMap[el]++;
            if (modeMap[el] > maxCount) {
                maxEl = el;
                maxCount = modeMap[el];
            }
        }
        return maxEl;
    }
    
    function maj(i: number, j: number, k: number): number {
        return mode([i, j, k]);
    }
    
    function rotr(x: Array<number>, n: number): Array<number> {
        return x.slice(-n).concat(x.slice(0, -n));
    }
    
    function shr(x: Array<number>, n: number): Array<number> {
        let out: Array<number> = [];
        for (let i = 0; i < n; i++) {
            out.push(0);
        }
        out = out.concat(x.slice(0, -n));
        return out;
    }
    
    function add(i: Array<number>, j: Array<number>): Array<number> {
        let length = i.length;
    
        let sums = [];
    
        let c = 0;
    
        for (let x = length - 1; x >= 0; x--) {
            sums.unshift(xorxor(i[x], j[x], c));
            c = maj(i[x], j[x], c);
        }
    
        return sums;
    }
    
    function _sha256(str: string): string {
        let maxValue = Math.pow(2, 32);
        let h_hex = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
        let k_hex = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
    
        let k = initializer(k_hex);
        let [h0, h1, h2, h3, h4, h5, h6, h7] = initializer(h_hex);
    
        let chunks = preprocessMessage(str);
        let chunk, i, w, j;
    
        let s0: Array<number>,
            s1: Array<number>,
            ch: Array<number>,
            temp1: Array<number>,
            temp2: Array<number>,
            m: Array<number>,
            a: Array<number>,
            b: Array<number>,
            c: Array<number>,
            d: Array<number>,
            e: Array<number>,
            f: Array<number>,
            g: Array<number>,
            h: Array<number>;
    
        let zeros32: Array<number> = [];
        for (i = 0; i < 32; i++) {
            zeros32.push(0);
        }
    
        for (let chunk_i = 0; chunk_i < chunks.length; chunk_i++) {
            chunk = chunks[chunk_i];
            w = chunker(chunk, 32);
    
            for (i = 0; i < 48; i++) {
                w.push(zeros32.slice());
            }
    
            for (i = 16; i < 64; i++) {
                s0 = XORXOR(rotr(w[i - 15], 7), rotr(w[i - 15], 18), shr(w[i - 15], 3));
                s1 = XORXOR(rotr(w[i - 2], 17), rotr(w[i - 2], 19), shr(w[i - 2], 10));
                w[i] = add(add(add(w[i - 16], s0), w[i - 7]), s1);
            }
    
            a = h0.slice();
            b = h1.slice();
            c = h2.slice();
            d = h3.slice();
            e = h4.slice();
            f = h5.slice();
            g = h6.slice();
            h = h7.slice();
    
            for (i = 0; i < 64; i++) {
                s1 = XORXOR(rotr(e, 6), rotr(e, 11), rotr(e, 25));
                ch = XOR(AND(e, f), AND(NOT(e), g));
                temp1 = add(add(add(add(h, s1), ch), k[i]), w[i]);
                s0 = XORXOR(rotr(a, 2), rotr(a, 13), rotr(a, 22));
                m = XORXOR(AND(a, b), AND(a, c), AND(b, c));
                temp2 = add(s0, m);
                h = g.slice();
                g = f.slice();
                f = e.slice();
                e = add(d, temp1);
                d = c.slice();
                c = b.slice();
                b = a.slice();
                a = add(temp1, temp2);
            }
    
            h0 = add(h0, a);
            h1 = add(h1, b);
            h2 = add(h2, c);
            h3 = add(h3, d);
            h4 = add(h4, e);
            h5 = add(h5, f);
            h6 = add(h6, g);
            h7 = add(h7, h);
        }
    
        let digest = "";
        let values = [h0, h1, h2, h3, h4, h5, h6, h7];
        
        for (i = 0; i < 8; i++) {
            digest += b2tob16(values[i]);
        }
    
        return digest;
    }

    /**
     * Calculates a SHA256 checksum
     */
    //% blockId=crypto_sha256 block="SHA256 $str"
    export function sha256(str: string): string {
        return _sha256(str);
    }
}