import crypto from 'crypto'
import {token, encodingAESKey, corpid} from './secret'

/**
 * 微信消息加解密
 * 
 * @class WXCrypto
 * @param {String} token          消息服务器设置的Token
 * @param {String} encodingAESKey 消息服务器设置的EncodingAESKey
 * @param {String} id             企业CorpId
 * @return {Object}
 */
class WXCrypto {
  private token: string;
  private AESKey: Buffer;
  private iv: Buffer;
  private id: string;
  constructor(token: string, encodingAESKey: string, id: string) {
    this.token = token;
    const key: Buffer = Buffer.from(encodingAESKey + "=", 'base64');
    if (key.length !== 32) {
      throw new Error('encodingAESKey invalid');
    }
    this.AESKey = key;
    this.iv = key.slice(0, 16);
    this.id = id;
  }
  /**
   * 获取签名
   * 
   * @for WXCrypto
   * @param {String} timestamp  时间戳
   * @param {String} nonce      随机数
   * @param {String} ciphertext 密文
   * @return {String}           签名
   */
  getSignature(timestamp: string, nonce: string, ciphertext: string): string {
    const sha1 = crypto.createHash('sha1');
    const arr = [this.token, timestamp, nonce, ciphertext].sort();
    sha1.update(arr.join(''));
    return sha1.digest('hex')
  }

  /**
   * 解密密文
   * 
   * @for WXCrypto
   * @param {String} ciphertext 密文
   * @return {String}           明文
   */
  decrypte(ciphertext: string): {message: string, id: string} {
    const decipher = crypto.createDecipheriv('aes-256-cbc', this.AESKey, this.iv);
    decipher.setAutoPadding(false);
    let plaintext = Buffer.concat([decipher.update(ciphertext, 'base64'), decipher.final()]);
    plaintext = pkcs7decode(plaintext)

    const content = plaintext.slice(16);
    const length = content.slice(0, 4).readUInt32BE(0);

    return {
      message: content.slice(4, length + 4).toString(),
      id: content.slice(length + 4).toString()
    }
  }

  /**
   * 加密明文
   * 
   * @for WXCrypto
   * @param {String} plaintext 明文
   * @return {String}          密文
   */
  encrypto(plaintext: string): string {
    // 获取16B的随机字符串
    const random= crypto.pseudoRandomBytes(16);

    const msg = Buffer.from(plaintext, 'utf-8');

    // 获取4B的内容长度的网络字节序
    var msgLength = Buffer.alloc(4);
    msgLength.writeUInt32BE(4, 0);

    const id = Buffer.from(this.id, 'ascii')
    const bufMsg = Buffer.concat([random, msgLength, msg, id]);

    // 对明文进行补位操作
    const encoded = pkcs7encode(bufMsg);
  
    // 创建加密对象，AES采用CBC模式，数据采用PKCS#7填充；IV初始向量大小为16字节，取AESKey前16字节
    const cipher = crypto.createCipheriv('aes-256-cbc', this.AESKey, this.iv);
    cipher.setAutoPadding(false);
  
    const cipheredMsg = Buffer.concat([cipher.update(encoded), cipher.final()]);
  
    // 返回加密数据的base64编码
    return cipheredMsg.toString('base64');
  }
}


/**
 * 使用PKCS#7删除解密后明文的补位字符
 * 
 * @param {Buffer} plaintext  明文
 * @return {Buffer}           最终输出的明文
 */
function pkcs7decode(plaintext: Buffer): Buffer {
  let pad = plaintext[plaintext.length - 1];

  if (pad < 1 || pad > 32) {
    pad = 0;
  }

  return plaintext.slice(0, plaintext.length - pad);
};

/**
 * 使用PKCS#7对需要加密的明文进行补位
 * 
 * @param {Buffer} plaintext  明文
 * @return {Buffer}           最终输出的明文
 */
function pkcs7encode (plaintext:Buffer): Buffer {
  const blockSize = 32;
  const length = plaintext.length;
  //计算需要填充的位数
  const amountToPad = blockSize - (length % blockSize);

  let result = Buffer.alloc(amountToPad);
  result.fill(amountToPad);

  return Buffer.concat([plaintext, result]);
};

const wxcrypto = new WXCrypto(token, encodingAESKey, corpid)
export default wxcrypto
