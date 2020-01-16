# wechat-work-crypto.js
企业微信消息加密/解密及验签的JavaScript实现

由于企业微信开放平台没有提供JavaScript实现的消息加解密及消息验证的方法，在[@JacksonTian JacksonTian](https://github.com/node-webot/wechat-crypto)的微信公众平台加解密库
基础上，我将一些过时的语法（如Buffer相关的语句）进行了修改，并使用TypeScript重写

提供了：消息加密，消息解密 （AES-266-cbc) 及消息验签三个方法
