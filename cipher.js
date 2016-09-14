"use strict";

function CipherPlay()
{
    let CipherPlay = this;

    // 基本编码处理
    this.basic = 
    {
        entitiesToUnicodes : function( sEntities )
        {
            sEntities = sEntities.replace(/\s/g, "");
            let reEntity = /&#\d+;/g,
                aMatch = [],
                nDecimalNum = 0,
                sHex = "",
                nHexLen = 0,
                aUnicodes = [];
            while( aMatch = reEntity.exec(sEntities) )
            {
                nDecimalNum = +( aMatch[0].slice(2, -1) );
                sHex = nDecimalNum.toString(16);
                nHexLen = sHex.length;
                sHex = nHexLen<4 ? "0000".slice(nHexLen)+sHex : sHex;
                aUnicodes.push( "\\u" + sHex );
            }
            return aUnicodes.join("");
        },
    };
    
    // Caesar
    this.Caesar = 
    {
        //加密，第二个参数为正或负的整数，表示加密的偏移位数
        encrypt: function(plainText, nDeviation)
        {
            var allChar = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"],
                sCiphertext = "",//待输出的密文
                plainText = plainText.toLocaleLowerCase(),
                len = plainText.length;
            
            for(var i=0; i<len; i++)
            {
                if( allChar.indexOf(plainText[i]) !== -1 )
                {
                    var cipherIndex = allChar.indexOf(plainText[i]) + nDeviation;//明文在字母表中的序号加上偏移位数等于密文在字母表中的序号
                    if( cipherIndex > 25 )//如果序号超过了字母表长度，则循环到字母表头部继续数
                    {
                        cipherIndex = cipherIndex - 26;
                    }
                    else if( cipherIndex < 0 )//如果是向左位移且移动超过了字母a的位置，则循环到字母表尾部继续数
                    {
                        cipherIndex = 26 + cipherIndex;
                    }
                    sCiphertext += allChar[cipherIndex];//将该为字母作为密文
                }
                else//如果该位不是英文字母，则照原样返回
                {
                    sCiphertext += plainText[i];
                }
            }
            return sCiphertext;
        },

        //破解
        //遍历密文所有25种偏移，查看有意义的一组
        crack: function (sCiphertext)
        {
            var len = sCiphertext.length,
                allChar = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"],
                sPlainText = "",//待输出明文
                aPlainText = [],//输出25组明文
                sCiphertext = sCiphertext.toLocaleLowerCase();
                
            for(var i=1; i<26; i++) //25种偏移
            {
                for(var j=0; j<len; j++)//遍历密文每个字符  
                {
                    if( allChar.indexOf(sCiphertext[j]) !== -1 )
                    {
                        var plainIndex = allChar.indexOf(sCiphertext[j]) + i;//偏移i位后的字母在字母表中的序号
                        if( plainIndex > 25 )//如果偏移超过了字母表长度
                        {
                            plainIndex = plainIndex - 26;   
                        }
                        sPlainText += allChar[plainIndex];//将偏移i位之后的字母加入明文字符串中
                    }
                    else//如果该位不是英文字母，则照原样返回
                    {
                        sPlainText += sCiphertext[j];
                    }
                } 
                aPlainText.push(sPlainText);//将偏移i位之后得到的字符串放入明文数组中
                sPlainText = "";//清空明文字符串，继续下一次偏移
            }
            return aPlainText;//返回25种偏移结果
        }
    };

    // Rail fence
    this.Railfence = 
    {
        //加密。第二个参数为几行加密。
        encrypt: function(sPlainText, lineNum)
        {
            var sPlainText = sPlainText.replace(/\s/g, "").toLocaleLowerCase(),
                aLine = new Array(lineNum),
                len = sPlainText.length,
                sResult = "";
            for(var a=0; a<lineNum; a++)//格式化为字符串，之后进行字符串拼接操作
            {
                aLine[a] = "";
            }
            for(var i=0; i<len; i++)//循环摆lineNum行
            {
                aLine[i%lineNum] += sPlainText.charAt(i);
            }
            for(var j=0; j<lineNum; j++)//拼接摆好的lineNum行字符串为一行
            {
                sResult += aLine[j];
            }
            return sResult;
        },

        //解密
        decrypt: function (sCiphertext, lineNum)
        {
            var sCiphertext = sCiphertext.replace(/\s/g, "").toLocaleLowerCase(),
                len = sCiphertext.length,
                aLine = [],
                sPlainText = "";
                
            var nLineSize = Math.floor(len/lineNum),//每行的长度。如果不能整除，这里表示长度较短的行的长度
                nLongLine = len%lineNum;//在不能整除的情况下，有几行长度是多一个字符的。
            
            var index = 0,
                i = 0;
            for(; i<lineNum; i++)//分行
            {
                //在不能均分的情况下，还原加密时的分行，上面的若干行长度要比下面的多一个，下面分两种情况
                if(i<nLongLine)//长度多一个的行    
                {
                    aLine[i] = sCiphertext.substr(index, nLineSize+1);
                    index += nLineSize+1;
                }
                else
                {
                    aLine[i] = sCiphertext.substr(index, nLineSize);
                    index += nLineSize;
                }
            }
            
            for(var j=0; j<nLineSize+1; j++)//逐列合并为明文
            {
                for(var k=0; k<lineNum; k++)//每一列的字符拼接并放入明文字符串
                {
                    if( aLine[k][j] )//较短的行最后一位是没有的
                    {
                        sPlainText += aLine[k][j];  
                    }
                }
            }
            return  sPlainText;      
        },

        //破解
        //对于长度为len的字符串，栅栏加密最多分为len-1行。按照这么多种情况逐一逆向到原字符串，寻找有意义的那一个或几个字符串
        crack: function (sCiphertext)
        {
            var sCiphertext = sCiphertext.replace(/\s/g, "").toLocaleLowerCase(),
                len = sCiphertext.length,
                aResult = [];
            for(var i=2; i<len; i++)//不知道是几行栅栏加密，这里逐一讨论完所有可能的情况
            {
                aResult[i-2] = "";//格式化为字符串之后进行拼接操作
                var aLine = CipherPlay.commonFunction.strSharing(sCiphertext, i),//针对每一种行数的加密算法，将密文分为相应的行数
                    size =  aLine[0].length;//分好行之后最宽的那一行或几行的宽度。如果不能均分，就会出现后面的若干行长度比这个少1
                for(var j=0; j<size; j++)//逐列组合字符，这个为栅栏逐列排列的逆过程
                {
                    for(var k=0; k<i; k++)//每一列从第一行到最后一行字符串拼接
                    {
                        if( !aLine[k][j] )//已经循环到第一个长度少一个的那行的少一个的那个位置，这里的值是undefined
                        {
                            break;  
                        }
                        aResult[i-2] += aLine[k][j];
                    }
                }
            }
            return aResult;
        }
    };

    // Virginia
    this.Virginia = 
    {
        //加密
        encrypt : function (plainText, key)//第二个参数为加密秘钥字符串
        {
            var plainText = plainText.replace(/\s/g, "").toLocaleLowerCase(),
                key = key.replace(/\s/g, "").toLocaleLowerCase();
                                      
            var pLen = plainText.length,
                kLen = key.length,
                cipherText = "";//待输出密文
            
            for(var i=0; i<pLen; i++)//遍历明文字符。在纵向中查找秘钥字符，在横向中查找明文字符
            {
                //因为秘钥要不断重复至明文长度，所以通过i%kLen循环遍历秘钥字符
                cipherText += VirginiaFormEncryption(key.charAt(i%kLen), plainText.charAt(i));
            }
            
            function VirginiaFormEncryption(sVirticalChar, sHorizontalChar)//单个字符，纵向字符和横向字符查找表中字符
            {
                //单独使用该函数时注意进行小写转化
                var allChar = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"];
                
                var charCodeV = allChar.indexOf(sVirticalChar),
                    charCodeH = allChar.indexOf(sHorizontalChar);
                
                return allChar[(charCodeV + charCodeH)%26];
            }
            
            return cipherText;
        },

        //解密
        decrypt: function (cipherText, key)//秘钥为未经重复的字符串
        {
            var cipherText = cipherText.replace(/\s/g, "").toLocaleLowerCase(),
                key = key.replace(/\s/g, "").toLocaleLowerCase();   
                
            var cLen = cipherText.length,
                kLen = key.length,
                plainText = "";//明文
            
            for(var i=0; i<cLen; i++)//遍历密文字符。在纵向中查找秘钥字符，在横向中查找密文字符
            {
                plainText += VirginiaFormDecryption(key.charAt(i%kLen), cipherText.charAt(i));
            }
            
            function VirginiaFormDecryption(sVirticalChar, sCipherChar)//纵向秘钥字符和对应的密文字符查找明文
            {
                //单独使用该函数时注意进行小写转化
                var allChar = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"];
                
                var charCodeV = allChar.indexOf(sVirticalChar),
                    charCodeC = allChar.indexOf(sCipherChar);
                
                return allChar[(charCodeC - charCodeV + 26)%26];
            }
            
            return plainText;
        }
    };


    //九宫格键盘加密//////////////////////////////////////////////////////////////////////////////////////
    /*
     *  原理：首先找到该英文字母在九宫格键盘所在的数字键，记为m；然后找到字母在该按键上的顺序，记为n。则mn为该字母对应的数字密文。
     *  例如：w对应的密文为91。
     */
    this.SquareKeyboard = 
    {
        //加密
        encrypt: function (plainText)//必须是纯字母
        {
            var aSquareKeyboard = ["", "", "abc", "def", "ghi", "jkl", "mno", "pqrs", "tuv", "wxyz"];//从0开始，10个数字键对应的字母
            
            var plainText = plainText.replace(/\s/g, "").toLocaleLowerCase(),
                len = plainText.length,
                cipherText = "",//待输出的密文
                bJBreak = false;
            var i = null,
                j = null,
                k = null;
            for(var i=0; i<len; i++)//以此循环所有的字母 
            {
                for(j=2; j<10; j++)//循环8有字母的按键  
                {
                    if(bJBreak)//k循环中已经找到，这里也可以跳出了
                    {
                        bJBreak = false;
                        break;  
                    }
                    for(k=0; k<4; k++)//循环每个按键上的字母，7和9最多四次  
                    {
                        if( plainText[i] ===    aSquareKeyboard[j][k] )//找到当前字符
                        {
                            cipherText += j +""+ (k+1);//将对应的两个数字加入密文。加一是因为数字键上字母序号从1开始记    
                            if( j!== 9 )//如果等于9，则本轮j循环已结束，没有机会变成false，下一轮会直接跳出，少计算一次
                            {
                                bJBreak = true;//一旦确定，k的循环要跳出，j的循环也要跳出
                            }
                            break;//确定之后跳出k循环
                        }
                    }
                }
            }
            return cipherText;
        },

        //解密
        decrypt: function (sNum)
        {   
            var aSquareKeyboard = ["", "", "abc", "def", "ghi", "jkl", "mno", "pqrs", "tuv", "wxyz"];//从0开始，10个数字键对应的字母
            if( typeof sNum === "number" )//如果参数是数字格式会被自从转化为指数形式，无法使用
            {
                sNum +="";  
            }
            var len = sNum.length,
                plainText = "";//待输出明文

            for(var i=0; i<len; i=i+2)//两两一组遍历,以上两行确定两个一组的数字对应的是什么字母
            {
                var temp = aSquareKeyboard[sNum[i]];//奇数位数字对应的九宫格按键
                plainText += temp[sNum[i+1]-1];//之后一位数字对应的当前数字键上的字母
            }
            return plainText;
        }
    };

    // 公共函数
    this.commonFunction = 
    {
        strSharing: function (str, n) // 均分字符串的函数
        {
            var len = str.length,
                size = 0,
                nShortLine = 0,
                aLine = [];
            
            size = Math.floor(len/n) === (len/n) ? (len/n) :　(Math.floor(len/n)+1);//排完后最长一行的长度，其他行可能也是这个长度，或者少一个
            nShortLine = n - (size*n - len);//长度完整的行数
            for(var i=0,index=0; i<n; i++)
            {
                if( i < nShortLine )//完整长度行
                {
                    aLine[i] = str.substr(index, size);
                    index += size;
                }
                else
                {
                    aLine[i] = str.substr(index, size-1);
                    index += size-1;
                }   
            }
            return aLine;
        }
    };
}