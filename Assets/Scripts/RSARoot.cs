﻿using System.Security.Cryptography;
using System.Text;
using System;

/************************************************************
 * 关于hashAlgorithm参数值有：MD5、SHA1、SHA256、SHA384、SHA512
 * 重要的事情说三遍，不懂的自己恶补去。
 * RSA加密解密：私钥解密，公钥加密。
 * RSA数字签名-俗称加签验签：私钥加签，公钥验签。  
 * RSA加密解密：私钥解密，公钥加密。
 * RSA数字签名-俗称加签验签：私钥加签，公钥验签。  
 * RSA加密解密：私钥解密，公钥加密。
 * RSA数字签名-俗称加签验签：私钥加签，公钥验签。 
 * ☆☆☆☆【注意这里所有的加密结果及加签结果都是base64的】☆☆☆☆☆
 */

public class RSARoot
{
    #region  加密
    /// <summary>
    /// RSA加密
    /// </summary>
    /// <param name="publicKeyJava"></param>
    /// <param name="data"></param>
    /// <returns></returns>
    public static string EncryptJava(string publicKeyJava, string data, string encoding = "UTF-8")
    {
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        byte[] cipherbytes;
        rsa.FromPublicKeyJavaString(publicKeyJava);

        //☆☆☆☆.NET 4.6以后特有☆☆☆☆
        //HashAlgorithmName hashName = new System.Security.Cryptography.HashAlgorithmName(hashAlgorithm);
        //RSAEncryptionPadding padding = RSAEncryptionPadding.OaepSHA512;//RSAEncryptionPadding.CreateOaep(hashName);//.NET 4.6以后特有               
        //cipherbytes = rsa.Encrypt(Encoding.GetEncoding(encoding).GetBytes(data), padding);
        //☆☆☆☆☆☆☆☆☆☆☆☆☆☆☆☆☆

        //☆☆☆☆.NET 4.6以前请用此段代码☆☆☆☆
        cipherbytes = rsa.Encrypt(Encoding.GetEncoding(encoding).GetBytes(data), false);

        return Convert.ToBase64String(cipherbytes);
    }
    /// <summary>
    /// RSA加密
    /// </summary>
    /// <param name="publicKeyCSharp"></param>
    /// <param name="data"></param>
    /// <returns></returns>
    public static string EncryptCSharp(string publicKeyCSharp, string data, string encoding = "UTF-8")
    {
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        byte[] cipherbytes;
        rsa.FromXmlString(publicKeyCSharp);

        //☆☆☆☆.NET 4.6以后特有☆☆☆☆
        //HashAlgorithmName hashName = new System.Security.Cryptography.HashAlgorithmName(hashAlgorithm);
        //RSAEncryptionPadding padding = RSAEncryptionPadding.OaepSHA512;//RSAEncryptionPadding.CreateOaep(hashName);//.NET 4.6以后特有               
        //cipherbytes = rsa.Encrypt(Encoding.GetEncoding(encoding).GetBytes(data), padding);
        //☆☆☆☆☆☆☆☆☆☆☆☆☆☆☆☆☆

        //☆☆☆☆.NET 4.6以前请用此段代码☆☆☆☆
        cipherbytes = rsa.Encrypt(Encoding.GetEncoding(encoding).GetBytes(data), false);

        return Convert.ToBase64String(cipherbytes);
    }

    /// <summary>
    /// RSA加密PEM秘钥
    /// </summary>
    /// <param name="publicKeyPEM"></param>
    /// <param name="data"></param>
    /// <returns></returns>
    public static string EncryptPEM(string publicKeyPEM, string data, string encoding = "UTF-8")
    {
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        byte[] cipherbytes;
        rsa.LoadPublicKeyPEM(publicKeyPEM);

        //☆☆☆☆.NET 4.6以后特有☆☆☆☆
        //HashAlgorithmName hashName = new System.Security.Cryptography.HashAlgorithmName(hashAlgorithm);
        //RSAEncryptionPadding padding = RSAEncryptionPadding.OaepSHA512;//RSAEncryptionPadding.CreateOaep(hashName);//.NET 4.6以后特有               
        //cipherbytes = rsa.Encrypt(Encoding.GetEncoding(encoding).GetBytes(data), padding);
        //☆☆☆☆☆☆☆☆☆☆☆☆☆☆☆☆☆

        //☆☆☆☆.NET 4.6以前请用此段代码☆☆☆☆
        cipherbytes = rsa.Encrypt(Encoding.GetEncoding(encoding).GetBytes(data), false);

        return Convert.ToBase64String(cipherbytes);
    }
    #endregion

    #region 解密
    /// <summary>
    /// RSA解密
    /// </summary>
    /// <param name="privateKeyJava"></param>
    /// <param name="content"></param>
    /// <returns></returns>
    public static string DecryptJava(string privateKeyJava, string data, string encoding = "UTF-8")
    {
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        byte[] cipherbytes;
        rsa.FromPrivateKeyJavaString(privateKeyJava);
        //☆☆☆☆.NET 4.6以后特有☆☆☆☆
        //RSAEncryptionPadding padding = RSAEncryptionPadding.CreateOaep(new System.Security.Cryptography.HashAlgorithmName(hashAlgorithm));//.NET 4.6以后特有        
        //cipherbytes = rsa.Decrypt(Encoding.GetEncoding(encoding).GetBytes(data), padding);
        //☆☆☆☆☆☆☆☆☆☆☆☆☆☆☆☆☆

        //☆☆☆☆.NET 4.6以前请用此段代码☆☆☆☆
        cipherbytes = rsa.Decrypt(Convert.FromBase64String(data), false);

        return Encoding.GetEncoding(encoding).GetString(cipherbytes);
    }
    /// <summary>
    /// RSA解密
    /// </summary>
    /// <param name="privateKeyCSharp"></param>
    /// <param name="content"></param>
    /// <returns></returns>
    public static string DecryptCSharp(string privateKeyCSharp, string data, string encoding = "UTF-8")
    {
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        byte[] cipherbytes;
        rsa.FromXmlString(privateKeyCSharp);
        //☆☆☆☆.NET 4.6以后特有☆☆☆☆
        //RSAEncryptionPadding padding = RSAEncryptionPadding.CreateOaep(new System.Security.Cryptography.HashAlgorithmName(hashAlgorithm));//.NET 4.6以后特有        
        //cipherbytes = rsa.Decrypt(Encoding.GetEncoding(encoding).GetBytes(data), padding);
        //☆☆☆☆☆☆☆☆☆☆☆☆☆☆☆☆☆

        //☆☆☆☆.NET 4.6以前请用此段代码☆☆☆☆
        cipherbytes = rsa.Decrypt(Convert.FromBase64String(data), false);

        return Encoding.GetEncoding(encoding).GetString(cipherbytes);
    }
    /// <summary>
    /// RSA解密
    /// </summary>
    /// <param name="privateKeyPEM"></param>
    /// <param name="content"></param>
    /// <returns></returns>
    public static string DecryptPEM(string privateKeyPEM, string data, string encoding = "UTF-8")
    {
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        byte[] cipherbytes;
        rsa.LoadPrivateKeyPEM(privateKeyPEM);
        //☆☆☆☆.NET 4.6以后特有☆☆☆☆
        //RSAEncryptionPadding padding = RSAEncryptionPadding.CreateOaep(new System.Security.Cryptography.HashAlgorithmName(hashAlgorithm));//.NET 4.6以后特有        
        //cipherbytes = rsa.Decrypt(Encoding.GetEncoding(encoding).GetBytes(data), padding);
        //☆☆☆☆☆☆☆☆☆☆☆☆☆☆☆☆☆

        //☆☆☆☆.NET 4.6以前请用此段代码☆☆☆☆
        cipherbytes = rsa.Decrypt(Convert.FromBase64String(data), false);

        return Encoding.GetEncoding(encoding).GetString(cipherbytes);
    }
    #endregion


    #region 加签
    /// <summary>
    /// RSA签名
    /// </summary>
    /// <param name="privateKeyJava">私钥</param>
    /// <param name="data">待签名的内容</param>
    /// <returns></returns>
    public static string RSASignJava(string data, string privateKeyJava, string hashAlgorithm = "MD5", string encoding = "UTF-8")
    {
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        rsa.FromPrivateKeyJavaString(privateKeyJava);//加载私钥
                                                     //RSAPKCS1SignatureFormatter RSAFormatter = new RSAPKCS1SignatureFormatter(rsa);
                                                     ////设置签名的算法为MD5 MD5withRSA 签名
                                                     //RSAFormatter.SetHashAlgorithm(hashAlgorithm);


        var dataBytes = Encoding.GetEncoding(encoding).GetBytes(data);
        var HashbyteSignature = rsa.SignData(dataBytes, hashAlgorithm);
        return Convert.ToBase64String(HashbyteSignature);

        //byte[] HashbyteSignature = ConvertToRgbHash(data, encoding);

        //byte[] dataBytes =Encoding.GetEncoding(encoding).GetBytes(data);
        //HashbyteSignature = rsa.SignData(dataBytes, hashAlgorithm);
        //return Convert.ToBase64String(HashbyteSignature);
        //执行签名 
        //EncryptedSignatureData = RSAFormatter.CreateSignature(HashbyteSignature);
        //return Convert.ToBase64String(RSAFormatter.CreateSignature(HashbyteSignature));
        //return result.Replace("=", String.Empty).Replace('+', '-').Replace('/', '_');
    }
    /// <summary>
    /// RSA签名
    /// </summary>
    /// <param name="privateKeyPEM">私钥</param>
    /// <param name="data">待签名的内容</param>
    /// <returns></returns>
    public static string RSASignPEM(string data, string privateKeyPEM, string hashAlgorithm = "MD5", string encoding = "UTF-8")
    {
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        rsa.LoadPrivateKeyPEM(privateKeyPEM);//加载私钥   
        var dataBytes = Encoding.GetEncoding(encoding).GetBytes(data);
        var HashbyteSignature = rsa.SignData(dataBytes, hashAlgorithm);
        return Convert.ToBase64String(HashbyteSignature);
    }
    /// <summary>
    /// RSA签名CSharp
    /// </summary>
    /// <param name="privateKeyCSharp">私钥</param>
    /// <param name="data">待签名的内容</param>
    /// <returns></returns>
    public static string RSASignCSharp(string data, string privateKeyCSharp, string hashAlgorithm = "MD5", string encoding = "UTF-8")
    {
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        rsa.FromXmlString(privateKeyCSharp);//加载私钥   
        var dataBytes = Encoding.GetEncoding(encoding).GetBytes(data);
        var HashbyteSignature = rsa.SignData(dataBytes, hashAlgorithm);
        return Convert.ToBase64String(HashbyteSignature);
    }
    #endregion

    #region 验签-方法一
    /// <summary> 
    /// 验证签名-方法一
    /// </summary>
    /// <param name="data"></param>
    /// <param name="signature"></param>
    /// <param name="encoding"></param>
    /// <returns></returns>
    public static bool VerifyJava(string data, string publicKeyJava, string signature, string hashAlgorithm = "MD5", string encoding = "UTF-8")
    {
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        //导入公钥，准备验证签名
        rsa.FromPublicKeyJavaString(publicKeyJava);
        //返回数据验证结果
        byte[] Data = Encoding.GetEncoding(encoding).GetBytes(data);
        byte[] rgbSignature = Convert.FromBase64String(signature);

        return rsa.VerifyData(Data, hashAlgorithm, rgbSignature);

        //return SignatureDeformatter(publicKeyJava, data, signature);

        //return CheckSign(publicKeyJava, data, signature);

        //return rsa.VerifyData(Encoding.GetEncoding(encoding).GetBytes(data), "MD5", Encoding.GetEncoding(encoding).GetBytes(signature));
    }
    /// <summary> 
    /// 验证签名PEM
    /// </summary>
    /// <param name="data"></param>
    /// <param name="signature"></param>
    /// <param name="encoding"></param>
    /// <returns></returns>
    public static bool VerifyPEM(string data, string publicKeyPEM, string signature, string hashAlgorithm = "MD5", string encoding = "UTF-8")
    {
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        //导入公钥，准备验证签名
        rsa.LoadPublicKeyPEM(publicKeyPEM);
        //返回数据验证结果
        byte[] Data = Encoding.GetEncoding(encoding).GetBytes(data);
        byte[] rgbSignature = Convert.FromBase64String(signature);

        return rsa.VerifyData(Data, hashAlgorithm, rgbSignature);
    }
    /// <summary> 
    /// 验证签名CSharp
    /// </summary>
    /// <param name="data"></param>
    /// <param name="signature"></param>
    /// <param name="encoding"></param>
    /// <returns></returns>
    public static bool VerifyCSharp(string data, string publicKeyCSharp, string signature, string hashAlgorithm = "MD5", string encoding = "UTF-8")
    {
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        //导入公钥，准备验证签名
        rsa.LoadPublicKeyPEM(publicKeyCSharp);
        //返回数据验证结果
        byte[] Data = Encoding.GetEncoding(encoding).GetBytes(data);
        byte[] rgbSignature = Convert.FromBase64String(signature);

        return rsa.VerifyData(Data, hashAlgorithm, rgbSignature);
    }
    #endregion

    #region 签名验证-方法二
    /// <summary>
    /// 签名验证
    /// </summary>
    /// <param name="publicKey">公钥</param>
    /// <param name="p_strHashbyteDeformatter">待验证的用户名</param>
    /// <param name="signature">注册码</param>
    /// <returns>签名是否符合</returns>
    public static bool SignatureDeformatter(string publicKey, string data, string signature, string hashAlgorithm = "MD5")
    {
        try
        {
            byte[] rgbHash = ConvertToRgbHash(data);
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            //导入公钥，准备验证签名
            rsa.FromPublicKeyJavaString(publicKey);

            RSAPKCS1SignatureDeformatter deformatter = new RSAPKCS1SignatureDeformatter(rsa);
            deformatter.SetHashAlgorithm("MD5");
            byte[] rgbSignature = Convert.FromBase64String(signature);
            if (deformatter.VerifySignature(rgbHash, rgbSignature))
            {
                return true;
            }
            return false;
        }
        catch
        {
            return false;
        }
    }
    /// <summary>
    /// 签名数据转化为RgbHash
    /// </summary>
    /// <param name="data"></param>
    /// <param name="encoding"></param>
    /// <returns></returns>
    public static byte[] ConvertToRgbHash(string data, string encoding = "UTF-8")
    {
        using (MD5 md5 = new MD5CryptoServiceProvider())
        {
            byte[] bytes_md5_in = Encoding.GetEncoding(encoding).GetBytes(data);
            return md5.ComputeHash(bytes_md5_in);
        }
    }
    #endregion

    #region 签名验证-方法三
    /// <summary>
    /// 验证签名
    /// </summary>
    /// <param name="data">原始数据</param>
    /// <param name="sign">签名</param>
    /// <returns></returns>
    public static bool CheckSign(string publicKey, string data, string sign, string encoding = "UTF-8")
    {

        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        rsa.FromPublicKeyJavaString(publicKey);
        MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();

        byte[] Data = Encoding.GetEncoding(encoding).GetBytes(data);
        byte[] rgbSignature = Convert.FromBase64String(sign);
        if (rsa.VerifyData(Data, md5, rgbSignature))
        {
            return true;
        }
        return false;
    }
    #endregion


}