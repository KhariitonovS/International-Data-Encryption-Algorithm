using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace Course
{
    public class IDEAManaged : SymmetricAlgorithm
    {
        public IDEAManaged()
            : base()
        {
            this.BlockSizeValue = 64;
            this.FeedbackSizeValue = this.BlockSizeValue;
            this.LegalBlockSizesValue = new KeySizes[] { new KeySizes(64, 64, 0) };
            this.LegalKeySizesValue = new KeySizes[] { new KeySizes(128, 128, 0) };
        }
        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        { return new IDEAManagedCryptor(rgbKey, rgbIV, false, ModeValue, PaddingValue); }
        public override ICryptoTransform CreateDecryptor() { return new IDEAManagedCryptor(this, false); }
        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        { return new IDEAManagedCryptor(rgbKey, rgbIV, true, ModeValue, PaddingValue); }
        public override ICryptoTransform CreateEncryptor() { return new IDEAManagedCryptor(this); }
        public override void GenerateIV()
        {
            IVValue = new byte[8];
            new RNGCryptoServiceProvider().GetBytes(IVValue);
        }
        public override void GenerateKey()
        {
            KeyValue = new byte[16];
            new RNGCryptoServiceProvider().GetBytes(KeyValue);
        }
    }
    public class IDEAManagedCryptor : ICryptoTransform
    {
        #region ctors
        public IDEAManagedCryptor(byte[] key, byte[] iv, bool Encryptor = true, CipherMode mode = CipherMode.ECB, PaddingMode PMode = PaddingMode.ISO10126)
        {
            if (key.Length != 16 || iv.Length != 8) throw new ArgumentException();
            SetKeys(key, iv);
            this.mode = mode;
            Encryption = Encryptor;
            pMode = PMode;
            GenerateSubKeys();
            Reset();
        }
        public IDEAManagedCryptor(IDEAManaged alg, bool Encryptor = true) : this(alg.Key, alg.IV, Encryptor, alg.Mode, alg.Padding) { }
        private void SetKeys(byte[] rKey, byte[] rIV)
        {
            key = new ushort[8];
            iv = new ushort[4];
            for (int i = 0; i < key.Length; i++) key[i] = (ushort)(((ushort)rKey[2 * i] << 8) | rKey[2 * i + 1]);
            for (int i = 0; i < iv.Length; i++) iv[i] = (ushort)(((ushort)rIV[2 * i] << 8) | rIV[2 * i + 1]);
        }
        ushort[] CircularShiftLeft(ushort[] A, int l)
        {
            ushort[] r = new ushort[A.Length], rt = new ushort[A.Length];
            r.Initialize();
            l %= A.Length * 16;
            int k1 = l % 16, n = l / 16;
            for (int i = 0; i < A.Length; i++) rt[i] = (ushort)(A[(i + n) % r.Length] << k1 | A[(i + n + 1) % r.Length] >> (16 - k1));
            return rt;
        }
        private void GenerateSubKeys()
        {
            ESubKeys = new ushort[9][];
            for (int i = 0; i < 9; i++) ESubKeys[i] = new ushort[6];
            ushort[][] b = new ushort[7][];
            b[0] = new ushort[8];
            key.CopyTo(b[0], 0);
            for (int i = 1; i < 7; i++) b[i] = CircularShiftLeft(b[i - 1], 25);
            for (int i = 0; i < 52; i++) ESubKeys[i / 6][i % 6] = b[i / 8][i % 8];
            if (!Encryption)
            {
                DSubKeys = new ushort[9][];
                for (int i = 0; i < 9; i++) DSubKeys[i] = new ushort[6];
                DSubKeys[0][0] = MULINV(ESubKeys[8][0]);
                DSubKeys[0][1] = ADDINV(ESubKeys[8][1]);
                DSubKeys[0][2] = ADDINV(ESubKeys[8][2]);
                DSubKeys[0][3] = MULINV(ESubKeys[8][3]);
                DSubKeys[0][4] = ESubKeys[7][4];
                DSubKeys[0][5] = ESubKeys[7][5];
                for (int i = 1; i < 8; i++)
                {
                    DSubKeys[i][0] = MULINV(ESubKeys[8 - i][0]);
                    DSubKeys[i][1] = ADDINV(ESubKeys[8 - i][2]);
                    DSubKeys[i][2] = ADDINV(ESubKeys[8 - i][1]);
                    DSubKeys[i][3] = MULINV(ESubKeys[8 - i][3]);
                    DSubKeys[i][4] = ESubKeys[7 - i][4];
                    DSubKeys[i][5] = ESubKeys[7 - i][5];
                }
                DSubKeys[8][0] = MULINV(ESubKeys[0][0]);
                DSubKeys[8][1] = ADDINV(ESubKeys[0][1]);
                DSubKeys[8][2] = ADDINV(ESubKeys[0][2]);
                DSubKeys[8][3] = MULINV(ESubKeys[0][3]);
            }
        }
        #endregion
        #region fields
        private ushort[] key, iv;
        private ushort[][] ESubKeys, DSubKeys;
        private ushort[] tmp;
        private bool Encryption;
        private CipherMode mode;
        private PaddingMode pMode;
        #endregion
        public void Reset() { tmp = iv; }
        #region cryptotransforminterface
        public bool CanReuseTransform { get { return object.ReferenceEquals(tmp, iv); } }
        public bool CanTransformMultipleBlocks { get { return mode == CipherMode.ECB; } }
        public int InputBlockSize { get { return 8; } }
        public int OutputBlockSize { get { return 8; } }
        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            if (inputCount < InputBlockSize) throw new ArgumentException();
            ushort[][] t = new ushort[inputCount / InputBlockSize][];
            int c = InputBlockSize / 2;
            for (int i = 0; i < t.Length; i++) t[i] = new ushort[c];
            ushort[][] e = new ushort[t.Length][];
            for (int i = 0; i < t.Length; i++)
            {
                e[i] = new ushort[c];
                for (int j = 0; j < InputBlockSize / 2; j++)
                    t[i][j] = (ushort)(inputBuffer[inputOffset + i * InputBlockSize + j * 2] << 8 |
                        inputBuffer[inputOffset + i * InputBlockSize + j * 2 + 1]);
            }
            switch (mode)
            {
                case CipherMode.ECB:
                    for (int i = 0; i < e.Length; i++)
                        e[i] = CryptBlock(t[i], Encryption ? ESubKeys : DSubKeys);
                    break;
                case CipherMode.CBC:
                    if (Encryption) for (int i = 0; i < e.Length; i++)
                        {
                            e[i] = CryptBlock(XOR(tmp, t[i]), ESubKeys);
                            tmp = t[i];
                        }
                    else for (int i = 0; i < e.Length; i++)
                        {
                            e[i] = XOR(tmp, CryptBlock(t[i], DSubKeys));
                            tmp = t[i];
                        }
                    break;
                case CipherMode.CFB:
                    if (Encryption) for (int i = 0; i < e.Length; i++)
                        {
                            tmp = CryptBlock(tmp, ESubKeys);
                            e[i] = tmp = XOR(t[i], tmp);
                        }
                    else for (int i = 0; i < e.Length; i++)
                        {
                            tmp = CryptBlock(tmp, ESubKeys);
                            e[i] = XOR(tmp, t[i]); tmp = t[i];
                        }
                    break;
                case CipherMode.OFB:
                    for (int i = 0; i < e.Length; i++)
                    {
                        tmp = CryptBlock(tmp, ESubKeys);
                        e[i] = XOR(t[i], tmp);
                    }
                    break;
                case CipherMode.CTS:
                    if (Encryption) for (int i = 0; i < e.Length; i++)
                        {
                            e[i] = CryptBlock(XOR(tmp, t[i]), ESubKeys);
                            tmp = XOR(t[i], e[i]);
                        }
                    else for (int i = 0; i < e.Length; i++)
                        {
                            e[i] = XOR(tmp, CryptBlock(t[i], DSubKeys));
                            tmp = XOR(t[i], e[i]);
                        }
                    break;
            }
            for (int i = 0; i < t.Length; i++)
                for (int j = 0; j < InputBlockSize / 2; j++)
                {
                    outputBuffer[outputOffset + i * OutputBlockSize + 2 * j] = (byte)(e[i][j] >> 8);
                    outputBuffer[outputOffset + i * OutputBlockSize + 2 * j + 1] = (byte)(e[i][j]);
                }
            return inputCount;
        }
        public void Dispose() { }
        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (inputCount == 0) return new byte[0];
            byte[] t = new byte[inputCount];
            for (int i = 0; i < t.Length; i++) t[i] = inputBuffer[inputOffset + i];
            byte[] e = new byte[t.Length];
            for (int i = 0; i < t.Length; i += InputBlockSize)
                TransformBlock(t, i, InputBlockSize, e, i);
            return e;
        }
        #endregion
        #region algorythm
        private ushort[] CryptBlock(ushort[] block, ushort[][] subkeys)
        {
            ushort[] res = new ushort[block.Length];
            block.CopyTo(res, 0);
            for (byte i = 0; i < 8; i++)
                Round(res, subkeys[i]);
            RoundFinal(res, subkeys[8]);
            return res;
        }
        private ushort[] XOR(ushort[] A, ushort[] B)
        {
            ushort[] r = new ushort[A.Length];
            for (int i = 0; i < r.Length; i++) r[i] = (ushort)(A[i] ^ B[i]);
            return r;
        }
        private void RoundFinal(ushort[] data, ushort[] keys)
        {
            ushort t = data[1];
            data[0] = MUL(data[0], keys[0]);
            data[1] = ADD(keys[1], data[2]);
            data[2] = ADD(keys[2], t);
            data[3] = MUL(data[3], keys[3]);
        }
        private void Round(ushort[] data, ushort[] keys)
        {
            data[0] = MUL(data[0], keys[0]);
            data[1] = ADD(data[1], keys[1]);
            data[2] = ADD(data[2], keys[2]);
            data[3] = MUL(data[3], keys[3]);
            ushort e = XOR(data[0], data[2]),
                f = XOR(data[1], data[3]), t;
            e = MUL(e, keys[4]);
            f = ADD(f, e);
            f = MUL(f, keys[5]);
            e = ADD(e, f);
            data[0] = XOR(data[0], f);
            t = data[1];
            data[1] = XOR(data[2], f);
            data[2] = XOR(t, e);
            data[3] = XOR(data[3], e);
        }
        #endregion
        #region math
        private ushort ADD(ushort A, ushort B) { return (ushort)(((int)A + (int)B) & 0x0000ffff); }
        private ushort MUL(ushort A, ushort B)
        {
            uint a = (uint)(A == 0 ? 0x00010000 : A),
                b = (uint)(B == 0 ? 0x00010000 : B),
                res = (a * b);
            res = res % 0x00010001;
            return (ushort)((res == 0x00010000) ? 0 : res);
        }
        private ushort XOR(ushort A, ushort B) { return (ushort)(A ^ B); }
        private ushort ADDINV(ushort A) { return (ushort)(~A + 1); }
        private ushort MULINV(ushort b)
        {
            int r1 = 0x10001, r2 = b,
                t1 = 0, t2 = 1;
            int q, r, t;
            while (r2 > 0)
            {
                q = r1 / r2;
                r = r1 - q * r2;
                r1 = r2;
                r2 = r;
                t = t1 - q * t2;
                t1 = t2;
                t2 = t;
            }
            while (t1 < 0) t1 += 0x00010001;
            return (ushort)(t1 & 0x0000ffff);
        }
        #endregion
        #region padding
        public byte[] AddPadding(byte[] inputBuffer)
        {
            int paddedCount = OutputBlockSize * (inputBuffer.Length / OutputBlockSize + 1);
            byte[] res = new byte[paddedCount];
            inputBuffer.CopyTo(res, 0);
            byte[] padd = new byte[paddedCount - inputBuffer.Length];
            if (padd.Length == 0) return res;
            padd.Initialize();
            switch (pMode)
            {
                case PaddingMode.ANSIX923:
                    padd[padd.Length - 1] = (byte)padd.Length;
                    break;
                case PaddingMode.ISO10126:
                    RNGCryptoServiceProvider r = new RNGCryptoServiceProvider();
                    r.GetBytes(padd);
                    padd[padd.Length - 1] = (byte)padd.Length;
                    break;
                case PaddingMode.PKCS7:
                    for (int i = 0; i < padd.Length; i++) padd[i] = (byte)(i + 1);
                    break;
            }
            for (int i = 0; i < padd.Length; i++) res[inputBuffer.Length + i] = padd[i];
            return res;
        }
        public byte[] RemovePadding(byte[] data)
        {
            int truelength = data.Length;
            switch (pMode)
            {
                case PaddingMode.ANSIX923:
                case PaddingMode.ISO10126:
                case PaddingMode.PKCS7:
                    if (data[data.Length - 1] > 8) throw new CryptographicException("Padding is not valid and cannot be removed");
                    truelength -= data[data.Length - 1];
                    break;
                default:
                    for (truelength--;
                        truelength > data.Length - OutputBlockSize && data[truelength] == 0;
                        truelength--) ;
                    truelength++;
                    break;
            }
            Array.Resize(ref data, truelength);
            return data;
        }
        #endregion
    }
}
