const SECRET = 'amazing';
const SECRET_LENGTH = SECRET.length;

const operate = (input) => {
  let result = "";
  for (let i in input) {
    result += String.fromCharCode(input.charCodeAt(i)^SECRET.charCodeAt(i%SECRET_LENGTH));
  }
  return result;
}

const decrypt = (encodedInput) => {  
  let input = Buffer.from(encodedInput, 'base64').toString();
  let dec = operate(input);
  console.log(dec);
  return dec;
}

const encrypt = (input) => {
  let enc = operate(input.toString());
  let b64 = Buffer.from(enc).toString('base64');
  console.log(b64);
  return b64;
}

