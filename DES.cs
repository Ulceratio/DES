using System;
//using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CipherNamespace
{
    class DES : ICipher
    {
        public byte[] Key { private get; set; }
        private List<BitArray> subKeys;

        public string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        public DES(byte[] Key)
        {
            this.Key = Key;
            subKeys = new List<BitArray>();
            setRoundKeys();
        }


        #region Шифрование
        public byte[] Encryption(byte[] objToEncrypt)
        {
            Func<BitArray,BitArray, BitArray> F = new Func<BitArray, BitArray, BitArray>((leftPart, rightPart) => {

                BitArray step1;

                BitArray step2;

                List<BitArray> step3;

                List<byte> step4;

                BitArray step5;

                BitArray tempVar;

                for (int i = 0; i < 16; i++)
                {
                    step1 = (BitArray)PermutationWithExtension((BitArray)rightPart.Clone()).Clone();
                    step2 = (BitArray)XorWithRoundKey((BitArray)step1.Clone(), i).Clone();
                    step3 = splitIntoEightParts((BitArray)step2.Clone());
                    step4 = sBlock(step3);
                    step5 = (BitArray)pBlock(step4).Clone();
                    tempVar = (BitArray)rightPart.Clone();
                    rightPart = (BitArray)step5.Clone() ^ (BitArray)leftPart.Clone();
                    leftPart = (BitArray)tempVar.Clone();
                }
                return rightPart.Union(leftPart);
            });

            Func<byte[], byte[]> processFunc = new Func<byte[], byte[]>((arr) => {
                var Parts = splitBlockIntoRightAndLeftPart(IP(new BitArray(arr)), 32);
                var leftPart = Parts.Item1;
                var rightPart = Parts.Item2;
                var resOfF = F(leftPart,rightPart);
                var afterEP = EP(resOfF);
                byte[] resultOfProcess = new byte[8];
                afterEP.CopyTo(resultOfProcess, 0);
                return resultOfProcess;
            });

            if (objToEncrypt.Length % 8 != 0)
            {
                int sourceLength = objToEncrypt.Length;
                int needToAddBytes = sourceLength + (8 - sourceLength % 8);
                byte[] newArray = new byte[needToAddBytes];
                objToEncrypt.CopyTo(newArray, 0);
                for (int i = sourceLength; i < needToAddBytes; i++)
                {
                    if (i == needToAddBytes - 1)
                    {
                        newArray[i] = (byte)(needToAddBytes - sourceLength);
                    }
                    else
                    {
                        newArray[i] = 0;
                    }
                }
                objToEncrypt = (byte[])newArray.Clone();
            }
            else
            {
                byte[] newArray = new byte[objToEncrypt.Length + 1];
                objToEncrypt.CopyTo(newArray, 0);
                for (int i = objToEncrypt.Length; i < newArray.Length; i++)
                {
                    newArray[i] = 0;
                }
                objToEncrypt = (byte[])newArray.Clone();
            }

            for (int i = 0; i < objToEncrypt.Length; i += 8)
            {
                try
                {
                    var startBytes = new byte[] { objToEncrypt[i], objToEncrypt[i + 1], objToEncrypt[i + 2], objToEncrypt[i + 3], objToEncrypt[i + 4], objToEncrypt[i + 5], objToEncrypt[i + 6], objToEncrypt[i + 7] };
                    processFunc(startBytes).CopyTo(objToEncrypt, i);
                    var endBytes = new byte[] { objToEncrypt[i], objToEncrypt[i + 1], objToEncrypt[i + 2], objToEncrypt[i + 3], objToEncrypt[i + 4], objToEncrypt[i + 5], objToEncrypt[i + 6], objToEncrypt[i + 7] };
                }
                catch (Exception ex)
                {
                    string msg = ex.Message;
                }

            }
            return objToEncrypt;
        }
        #endregion

        #region Дешифрование
        public byte[] Decryption(byte[] objToDecrypt)
        {
            byte[] newArray = new byte[objToDecrypt.Length - (objToDecrypt[objToDecrypt.Length - 1] == 0 ? 1 : objToDecrypt[objToDecrypt.Length - 1])];

            Func<BitArray, BitArray, BitArray> F = new Func<BitArray, BitArray, BitArray>((leftPart, rightPart) => {

                BitArray step1;

                BitArray step2;

                List<BitArray> step3;

                List<byte> step4;

                BitArray step5;

                BitArray tempVar;

                for (int i = 15; i >= 0; i--)
                {
                    step1 = (BitArray)PermutationWithExtension((BitArray)rightPart.Clone()).Clone();
                    step2 = (BitArray)XorWithRoundKey((BitArray)step1.Clone(), i).Clone();
                    step3 = splitIntoEightParts((BitArray)step2.Clone());
                    step4 = sBlock(step3);
                    step5 = (BitArray)pBlock(step4).Clone();
                    tempVar = (BitArray)rightPart.Clone();
                    rightPart = (BitArray)step5.Clone() ^ (BitArray)leftPart.Clone();
                    leftPart = (BitArray)tempVar.Clone();
                }
                return rightPart.Union(leftPart);
            });

            Func<byte[], byte[]> processFunc = new Func<byte[], byte[]>((arr) => {
                var Parts = splitBlockIntoRightAndLeftPart(IP(new BitArray(arr)), 32);
                var leftPart = Parts.Item1;
                var rightPart = Parts.Item2;
                var resOfF = F(leftPart, rightPart);
                var afterEP = EP(resOfF);
                byte[] resultOfProcess = new byte[8];
                afterEP.CopyTo(resultOfProcess, 0);
                return resultOfProcess;
            });


            for (int i = 0; i < objToDecrypt.Length; i += 8)
            {
                try
                {
                    processFunc(new byte[] { objToDecrypt[i], objToDecrypt[i + 1], objToDecrypt[i + 2], objToDecrypt[i + 3], objToDecrypt[i + 4], objToDecrypt[i + 5], objToDecrypt[i + 6], objToDecrypt[i + 7] }).CopyTo(objToDecrypt, i);
                }
                catch
                {}
                
            }

            //int howMuchWasAdded = ob

            for (int i = 0; i < newArray.Length; i++)
            {
                newArray[i] = objToDecrypt[i];
            }

            objToDecrypt = (byte[])newArray.Clone();

            return objToDecrypt;
        }
        #endregion

        #region extra func
        private BitArray IP(BitArray sourceArray)
        {
            //58,60,62,64,57,59,61,63,
            //50,52,54,56,49,51,53,55,
            //42,44,46,48,41,43,45,47,
            //34,36,38,40,33,35,37,39,
            //26,28,30,32,25,27,29,31,
            //18,20,22,24,17,19,21,23,
            //10,12,14,16,9,11,13,15,
            //2,4,6,8,1,3,5,7
            int[] Permutation =
            {
                58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7
            };
            sourceArray.applyPermutations(Permutation);
            return (BitArray)sourceArray.Clone();
        }

        private Tuple<BitArray,BitArray> splitBlockIntoRightAndLeftPart(BitArray sourceArray,int sizeOfBlock) //32|28
        {
            BitArray leftPart = new BitArray(sizeOfBlock);
            BitArray rightPart = new BitArray(sizeOfBlock);
            Parallel.For(0, sourceArray.Count, (i) => {
                if(i < sizeOfBlock)
                {
                    leftPart[i] = sourceArray[i];
                }
                else
                {
                    rightPart[i - sizeOfBlock] = sourceArray[i];
                }
            });
            return new Tuple<BitArray, BitArray>((BitArray)leftPart.Clone(), (BitArray)rightPart.Clone());
        }
        #endregion


        #region Фнукция F
        private BitArray PermutationWithExtension(BitArray rightPart)
        {
            int[] Permutation = new int[48]
            {
                32, 1, 2, 3, 4, 5,
                4, 5, 6, 7, 8, 9,
                8, 9, 10, 11, 12, 13,
                12, 13, 14, 15, 16, 17,
                16, 17, 18, 19, 20, 21,
                20, 21, 22, 23, 24, 25,
                24, 25, 26, 27, 28, 29,
                28, 29, 30, 31, 32, 1
            };
            rightPart.applyPermutations(Permutation);
            return (BitArray)rightPart.Clone();
        }

        private BitArray XorWithRoundKey(BitArray sourceArray,int round)
        {
            BitArray roundKey = subKeys[round];
            return sourceArray ^ roundKey;
        }

        private List<BitArray> splitIntoEightParts(BitArray sourceArray)
        {
            List<BitArray> result = new List<BitArray>();
            BitArray tempArray;
            tempArray = new BitArray(6);
            //Parallel.For(0, sourceArray.Length, (i) => 
            for (int i = 0; i < sourceArray.Count; i++)
            {
                if (i < 6)//0
                {
                    tempArray[i] = sourceArray[i];
                    if(i == 5)
                    {
                        result.Add((BitArray)tempArray.Clone());
                        tempArray = new BitArray(6);
                    }
                }

                if(i >= 6 && i < 12)//1
                {
                    tempArray[i - 6] = sourceArray[i];
                    if (i == 11)
                    {
                        result.Add((BitArray)tempArray.Clone());
                        tempArray = new BitArray(6);
                    }
                }

                if (i >= 12 && i < 18)//2
                {
                    tempArray[i - 12] = sourceArray[i];
                    if (i == 17)
                    {
                        result.Add((BitArray)tempArray.Clone());
                        tempArray = new BitArray(6);
                    }
                }

                if (i >= 18 && i < 24)//3
                {
                    tempArray[i - 18] = sourceArray[i];
                    if (i == 23)
                    {
                        result.Add((BitArray)tempArray.Clone());
                        tempArray = new BitArray(6);
                    }
                }

                if (i >= 24 && i < 30)//4
                {
                    tempArray[i - 24] = sourceArray[i];
                    if (i == 29)
                    {
                        result.Add((BitArray)tempArray.Clone());
                        tempArray = new BitArray(6);
                    }
                }

                if (i>=30 && i < 36)//5
                {
                    tempArray[i - 30] = sourceArray[i];
                    if (i == 35)
                    {
                        result.Add((BitArray)tempArray.Clone());
                        tempArray = new BitArray(6);
                    }
                }

                if (i>=36 && i < 42)//6
                {
                    tempArray[i - 36] = sourceArray[i];
                    if (i == 41)
                    {
                        result.Add((BitArray)tempArray.Clone());
                        tempArray = new BitArray(6);
                    }
                }

                if (i >= 42 && i < 48)//6
                {
                    tempArray[i - 42] = sourceArray[i];
                    if (i == 47)
                    {
                        result.Add((BitArray)tempArray.Clone());
                        tempArray = new BitArray(6);
                    }
                }
            }
            return result;
        }

        private int getIntFromBitArray(BitArray bitArray)
        {

            if (bitArray.Count > 32)
                throw new ArgumentException("Argument length shall be at most 32 bits.");

            byte[] temp = new byte[7];
            bitArray.CopyTo(temp, 0);

            return BitConverter.ToInt32(temp,0);
        }

        private List<byte> sBlock(List<BitArray> sourceList)
        {
            List<Func<BitArray, byte>> sBlockFunctions = new List<Func<BitArray, byte>>();

            Func<BitArray, Tuple<int, int>> findSubstitution = (sourceArray) =>
              {
                  BitArray twoBits = new BitArray(2);
                  BitArray fourBits = new BitArray(4);

                  twoBits[0] = sourceArray[0];
                  twoBits[1] = sourceArray[5];

                  fourBits[0] = sourceArray[1];
                  fourBits[1] = sourceArray[2];
                  fourBits[2] = sourceArray[3];
                  fourBits[3] = sourceArray[4];

                  return new Tuple<int, int>(twoBits.getByteValueOFBitArray, fourBits.getByteValueOFBitArray);
              };
            #region s- blocks
            sBlockFunctions.Add(new Func<BitArray, byte>((sourceArray) =>
            {
                int[,] Substitution = new int[4, 16]
                {
                    {14 ,4 ,13 ,1 ,2 ,15 ,11 ,8 ,3 ,10 ,6 ,12 ,5 ,9 ,0 ,7},
                    {0, 15 ,7, 4, 14, 2, 13, 1, 10, 6 ,12 ,11, 9, 5, 3, 8},
                    {4, 1, 14, 8 ,13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                    {15 ,12, 8 ,2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6 ,13}
                };
                Tuple<int, int> IJ = findSubstitution(sourceArray);
                return (byte)Substitution[IJ.Item1,IJ.Item2];
            })); // 1

            sBlockFunctions.Add(new Func<BitArray, byte>((sourceArray) =>
            {
                int[,] Substitution = new int[4, 16]
                {
                    {15 ,1 ,8 ,14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                    {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                    {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                    {13, 8, 10, 1, 3 ,15, 4, 2 ,11, 6 ,7 ,12, 0, 5, 14, 9}
                };
                Tuple<int, int> IJ = findSubstitution(sourceArray);
                return (byte)Substitution[IJ.Item1, IJ.Item2];
            })); //2

            sBlockFunctions.Add(new Func<BitArray, byte>((sourceArray) =>
            {
                int[,] Substitution = new int[4, 16]
                {
                    {10, 0, 9, 14, 6, 3 ,15, 5, 1, 13, 12, 7 ,11, 4, 2, 8},
                    {13, 7 ,  0  , 9  , 3 ,  4 ,  6 ,  10,  2  , 8  , 5  , 14 , 12 , 11 , 15 , 1},
                    {13, 6  , 4  , 9 ,  8  , 15 , 3 ,  0  , 11 , 1 ,  2  , 12,  5,   10 , 14 , 7},
                    {1 , 10 , 13 , 0  , 6,   9 ,  8 ,  7 ,  4 ,  15 , 14,  3  , 11 , 5 ,  2  , 12  }
                };
                Tuple<int, int> IJ = findSubstitution(sourceArray);
                return (byte)Substitution[IJ.Item1, IJ.Item2];
            })); //3

            sBlockFunctions.Add(new Func<BitArray, byte>((sourceArray) =>
            {
                int[,] Substitution = new int[4, 16]
                {
                    {7 , 13,  14,  3 ,  0 ,  6   ,9 ,  10 , 1 ,  2  , 8  , 5 ,  11 , 12  ,4   ,15},
                    {13, 8 ,  11,  5  , 6  , 15,  0,   3 ,  4  , 7 ,  2  , 12 , 1 ,  10,  14,  9},
                    {10, 6,   9  , 0  , 12,  11 , 7 ,  13,  15,  1,   3 ,  14,  5 ,  2,   8 ,  4},
                    {3 , 15 , 0 ,  6  , 10,  1 ,  13,  8  , 9 ,  4 ,  5 ,  11,  12,  7 ,  2 ,  14  }
                };
                Tuple<int, int> IJ = findSubstitution(sourceArray);
                return (byte)Substitution[IJ.Item1, IJ.Item2];
            })); //4

            sBlockFunctions.Add(new Func<BitArray, byte>((sourceArray) =>
            {
                int[,] Substitution = new int[4, 16]
                {
                    {2  ,12,  4  , 1 ,  7  , 10  ,11,  6  , 8  , 5  , 3  , 15  ,13 , 0  , 14 , 9   },
                    {14, 11,  2 ,  12 , 4  , 7 ,  13,  1,   5,   0,   15,  10,  3,   9 ,  8 ,  6},
                    {4,  2 ,  1 ,  11 , 10  ,13 , 7 ,  8 ,  15 , 9  , 12,  5 ,  6 ,  3 ,  0 ,  14},
                    {11 ,8  , 12 , 7 ,  1  , 14 , 2 ,  13,  6  , 15 , 0  , 9  , 10  ,4 ,  5 ,  3}
                };
                Tuple<int, int> IJ = findSubstitution(sourceArray);
                return (byte)Substitution[IJ.Item1, IJ.Item2];
            }));//5

            sBlockFunctions.Add(new Func<BitArray, byte>((sourceArray) =>
            {
                int[,] Substitution = new int[4, 16]
                {
                    {12 ,1   ,10  ,15 , 9 ,  2   ,6  , 8 ,  0 ,  13,  3 ,  4 ,  14 , 7 ,  5  , 11  },
                    {10 ,15,  4 ,  2 ,  7 ,  12 , 9  , 5  , 6  , 1  , 13 , 14,  0 ,  11 , 3 ,  8},
                    {9,  14  ,15 , 5  , 2  , 8  , 12 , 3 ,  7 ,  0  , 4 ,  10 , 1  , 13 , 11 , 6},
                    {4 , 3 ,  2 ,  12,  9,   5 ,  15 , 10 , 11,  14 , 1 ,  7 ,  6  , 0 ,  8  , 13}
                };
                Tuple<int, int> IJ = findSubstitution(sourceArray);
                return (byte)Substitution[IJ.Item1, IJ.Item2];
            }));//6

            sBlockFunctions.Add(new Func<BitArray, byte>((sourceArray) =>
            {
                int[,] Substitution = new int[4, 16]
                {
                    {4 , 11 , 2 ,  14,  15 , 0,   8 ,  13,  3 ,  12,  9 ,  7 ,  5 ,  10  ,6  , 1},
                    {13 ,0   ,11,  7 ,  4,   9 ,  1 ,  10 , 14 , 3  , 5  , 12,  2  , 15 , 8  , 6},
                    {1 , 4 ,  11,  13 , 12  ,3 ,  7 ,  14  ,10 , 15 , 6,   8 ,  0 ,  5,   9,   2},
                    {6,  11  ,13,  8 ,  1   ,4  , 10  ,7  , 9,   5 ,  0 ,  15 , 14,  2 ,  3 ,  12  }
                };
                Tuple<int, int> IJ = findSubstitution(sourceArray);
                return (byte)Substitution[IJ.Item1, IJ.Item2];
            }));//7

            sBlockFunctions.Add(new Func<BitArray, byte>((sourceArray) =>
            {
                int[,] Substitution = new int[4, 16]
                {
                    {13 ,2 ,  8 ,  4 ,  6  , 15 , 11,  1 ,  10  ,9  , 3  , 14,  5  , 0  , 12,  7   },
                    {1 , 15 , 13,  8 ,  10,  3,   7 ,  4 ,  12,  5,   6,   11,  0 ,  14 , 9,   2},
                    {7,  11,  4 ,  1 ,  9 ,  12  ,14 , 2 ,  0  , 6,   10,  13,  15,  3,   5 ,  8   },
                    {2 , 1 ,  14 , 7 ,  4 ,  10,  8  , 13  ,15 , 12,  9 ,  0  , 3 ,  5 ,  6 ,  11}
                };
                Tuple<int, int> IJ = findSubstitution(sourceArray);
                return (byte)Substitution[IJ.Item1, IJ.Item2];
            }));//8
            #endregion

            List<byte> result = new List<byte>();

            for (int i = 0; i < sourceList.Count; i++)
            {
                result.Add(sBlockFunctions[i](sourceList[i]));
            }
            
            return result;
        }

        private BitArray pBlock(List<byte> sourceList)
        {
            sourceList.Reverse();
            BitArray array = new BitArray(sourceList.ToArray(), 4);
            int[] Permutation = new int[32]
            {
                16, 7, 20, 21,
                29, 12, 28, 17,
                1, 15, 23, 26,
                5, 18, 31, 10,
                2, 8, 24, 14,
                32, 27, 3, 9,
                19, 13, 30, 6,
                22, 11, 4, 25
            };
            array.applyPermutations(Permutation);
            return (BitArray)array.Clone();
        }

        private BitArray UniteParts(BitArray leftPart,BitArray rightPart,int resLength)
        {
            BitArray array = new BitArray(resLength);
            for (int i = 0; i < resLength; i++)
            {
                if(i < resLength/2)
                {
                    array[i] = leftPart[i];
                }
                else
                {
                    array[i] = rightPart[i - resLength / 2];
                }
            }
            return (BitArray)array.Clone();
        }

        private BitArray EP(BitArray sourceArray)
        {
            int[] Permutation = new int[64]
            {
                40 , 8 ,  48 , 16,  56,  24 , 64 , 32,  39 , 7 ,  47 , 15 , 55 , 23 , 63,  31,
                38 , 6 ,  46 , 14,  54,  22 , 62 , 30,  37,  5 ,  45,  13 , 53 , 21 , 61,  29,
                36 , 4 ,  44 , 12 , 52 , 20 , 60 , 28 , 35,  3 ,  43 , 11 , 51 , 19 , 59 , 27,
                34 , 2 ,  42 , 10 , 50 , 18 , 58 , 26 , 33,  1 ,  41 , 9  , 49 , 17 , 57 , 25
            };
            BitArray tempArray = new BitArray(64);
            for (int i = 0; i < sourceArray.Count; i++)
            {
                tempArray[i] = sourceArray[Permutation[i] - 1];
            }
            return (BitArray)tempArray.Clone();
        }
        #endregion

        #region Разворачивание ключа
        private void setRoundKeys()
        {
            BitArray temparr = new BitArray(Key);

            int[] shiftArr = new int[16] { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1, };

            BitArray tempCi = new BitArray(28);
            BitArray tempDi = new BitArray(28);

            Tuple<BitArray, BitArray> tempParts = splitBlockIntoRightAndLeftPart(PC1Block(temparr), 28);

            tempCi = tempParts.Item1;
            tempDi = tempParts.Item2;

            for (int i = 1; i <= 16; i++)
            {
                tempCi = tempCi << shiftArr[i - 1];
                tempDi = tempDi << shiftArr[i - 1];
                subKeys.Add(PC2Block(UniteParts(tempCi, tempDi, 56)));
            }
            tempCi = null;
            tempDi = null;
        }

        private BitArray PC1Block(BitArray sourceArray)
        {
            int[] PC1 = new int[56]
            {
                57 , 49 , 41 , 33 , 25 , 17 , 9  , 1 ,  58 , 50 , 42 , 34 , 26 , 18 ,
                10 , 2  , 59 , 51 , 43 , 35 , 27 , 19 , 11 , 3  , 60 , 52 , 44 , 36,
                63 , 55 , 47 , 39 , 31 , 23 , 15 , 7  , 62 , 54 , 46 , 38 , 30 , 22  ,
                14 , 6 ,  61 , 53 , 45 , 37 , 29 , 21  ,13 , 5  , 28 , 20 , 12 , 4
            };
            sourceArray.applyPermutations(PC1);
            return (BitArray)sourceArray.Clone();
        }

        private BitArray PC2Block(BitArray sourceArray)
        {
            int[] PC2 = new int[48]
            {
                14,  17 , 11 , 24,  1 ,  5 ,  3 ,  28 , 15,  6 ,  21 , 10,  23 , 19,  12,  4,
                26,  8  , 16 , 7 ,  27 , 20,  13,  2  , 41  ,52,  31 , 37 , 47 , 55,  30,  40,
                51 , 45 , 33 , 48 , 44 , 49 , 39,  56  ,34 , 53 , 46 , 42 , 50 , 36,  29,  32
            };

            sourceArray.applyPermutations(PC2);
            return (BitArray)sourceArray.Clone();
        }
        #endregion

        private string show(BitArray array)
        {
            string res = "";
            for (int i = 0; i < array.Count; i++)
            {
                res += array[i] == true ? "1" : "0";
            }
            return res;
        }
    }
}
