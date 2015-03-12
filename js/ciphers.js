function toHTML(holder, result)
{
	holder.empty();
	holder.append(result);
}

function GCD(a, b) 
{
    if (b.notEquals(0))
        return GCD(b, bigInt(a.mod(b)));
	else
        return a.notEquals(1);
}

function intToAscii(num)
{
	var out = '';
	num = num + '';
	var arr = num.match(/.{1,3}/g);
	
	for(var i = 0; i < arr.length; i++)
		out = out + String.fromCharCode(arr[i]);
	
	return out;
}

function asciiToInt(str)
{
	var out = '';
	for(var i = 0; i < str.length; i++)
		out = out + '' + str.charCodeAt(i);
	
	return out;
}

var RSA = {
	setBase: function(p, q)
	{			
		this.p = bigInt(p + '');
		this.q = bigInt(q + '');
		this.n = bigInt(this.p.times(this.q).toString());
		this.r = bigInt(bigInt(this.p.minus(1)).multiply(bigInt(this.q.minus(1))));
		
		//console.log('n = ' + this.n.toString() + ', r = ' + this.r.toString());
		return true;
	},
	chooseKeys: function()
	{
		var e = bigInt(1);
		var d = bigInt(2);
		
		while(e.lesser(this.n))
		{
			e = bigInt(e.next());
			
			if(GCD(e, this.r))//Common divisor found. Not ok.
				continue;
			
			var f = 1;
			while(this.r.times(f).add(1).divmod(e).remainder != 0)
				f++;
			break;
		}
		this.e = e;
		this.d = d = this.r.times(f).add(1).divide(e);
		
		return e.times(d).mod(this.r).equals(1);
	},
	checkMessage: function(m, n)
	{
		var i_m = bigInt(asciiToInt(m));
		if(i_m.greater(n))
			return false;
		return true;
	},
	setup: function(p,q)
	{
		this.setBase(p,q);
		
		if(!this.chooseKeys())
			return {error: 'Damnit, cant find any keys.'};
			
		return {e: Base64.encode(this.e.toString()), d: Base64.encode(this.d.toString()), n: this.n.toString()};
	},
	encrypt: function(m, e, n)
	{
		var i_m = bigInt(asciiToInt(m));
		var e = bigInt(Base64.decode(e));
		var n = bigInt(n);
		if(!this.checkMessage(m, n))
			return {error: 'Message too big (' + i_m.toString() + '). It has to be smaller than ' + this.n.toString() + '.'};

		var c_int = i_m.pow(e).mod(n).toString();
		console.log(c_int);
		return {c: Base64.encode(c_int)};
	},
	decrypt: function(c, d, n)
	{
		var c = bigInt(Base64.decode(c));
		console.log(c.toString());
		var i_m = c.pow(bigInt(Base64.decode(d))).divmod(bigInt(n));
		
		console.log(i_m.remainder.toString());
		return intToAscii(i_m.remainder.toString());
	}
}


var Vigenere = {
	chars: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
	generate: function(str, key)
	{	
		return this.runString(str, key, 'getCharDiffGenerate');
	},
	solve: function(str, key)
	{
		return this.runString(str, key, 'getCharDiffSolve');
	},
	runString: function(str, key, diff_function)
	{
		var pattern = new RegExp('^([' + this.chars + ']+)$', 'i');
		var neg_pattern = new RegExp('^([^' + this.chars + ']+)$', 'i');
		//if(!pattern.test(str) || !pattern.test(key))
		//	return 'Not valid input. Valid chars are: ' + this.chars + '. No spaces.';
		
		var str = str.toUpperCase();	
		var key = this.padKey(str.length, key.toUpperCase());
		var matches = str.replace(neg_pattern, '');
		var out = '';
		
		for(var i = 0; i < matches.length; i++)
		{	
			var ref_char_index = this.chars.indexOf(matches.charAt(i));
			var key_char_index = this.chars.indexOf(key.charAt(i));
			
			var result_index = this[diff_function](ref_char_index, key_char_index);
			var result_char = this.chars.charAt(result_index);
			out = out + result_char;
		}
		return out;
	},
	getCharDiffSolve: function(p_index, c_index)
	{
		if(p_index >= c_index)
			return p_index - c_index;
		
		return p_index - (c_index - this.chars.length);
	},
	getCharDiffGenerate: function(p_index, c_index)
	{
		return (p_index + c_index)%this.chars.length;
	},
	padKey: function(len, key)
	{
		if(len == key.length)
			return key;
			
		if(len < key.length)
			return key.substring(0, len);
		
		return this.padKey(len, key + '' + key);
	}
}



var ROT = {
	chars: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
	generate: function(plaintext, shift)
	{
		var ciphertext = this.rotate(plaintext, parseInt(shift));
		return ciphertext;
	},
	solve: function(ciphertext, shift)
	{
		var plaintext = this.rotate(ciphertext, -1*parseInt(shift));
		return plaintext;
	},
	rotate: function(str, shift, pos)
	{
		var pos = pos || 0;
		
		if(!str.length)
			return '';
		
		var old_char = str.charAt(pos);
		var old_pos = this.chars.indexOf(old_char.toUpperCase());

		if(old_pos < 0)//Some other character
			return old_char.toUpperCase() + this.rotate(str, shift, pos+1);
		
		var new_pos = (old_pos + shift) % this.chars.length;
		new_pos = new_pos < 0 ? this.chars.length + new_pos : new_pos;
		
		var new_char = this.chars.charAt(new_pos);

		if(str.length-1 > pos)
			return new_char + this.rotate(str, shift, pos+1);
			
		return new_char;
	}
}



/**
*
*  Base64 encode / decode
*  http://www.webtoolkit.info/
*
**/
var Base64 = {

// private property
_keyStr : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",

// public method for encoding
encode : function (input) {
    var output = "";
    var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
    var i = 0;

    input = Base64._utf8_encode(input);

    while (i < input.length) {

        chr1 = input.charCodeAt(i++);
        chr2 = input.charCodeAt(i++);
        chr3 = input.charCodeAt(i++);

        enc1 = chr1 >> 2;
        enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
        enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
        enc4 = chr3 & 63;

        if (isNaN(chr2)) {
            enc3 = enc4 = 64;
        } else if (isNaN(chr3)) {
            enc4 = 64;
        }

        output = output +
        this._keyStr.charAt(enc1) + this._keyStr.charAt(enc2) +
        this._keyStr.charAt(enc3) + this._keyStr.charAt(enc4);

    }

    return output;
},

// public method for decoding
decode : function (input) {
    var output = "";
    var chr1, chr2, chr3;
    var enc1, enc2, enc3, enc4;
    var i = 0;

    input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");

    while (i < input.length) {

        enc1 = this._keyStr.indexOf(input.charAt(i++));
        enc2 = this._keyStr.indexOf(input.charAt(i++));
        enc3 = this._keyStr.indexOf(input.charAt(i++));
        enc4 = this._keyStr.indexOf(input.charAt(i++));

        chr1 = (enc1 << 2) | (enc2 >> 4);
        chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
        chr3 = ((enc3 & 3) << 6) | enc4;

        output = output + String.fromCharCode(chr1);

        if (enc3 != 64) {
            output = output + String.fromCharCode(chr2);
        }
        if (enc4 != 64) {
            output = output + String.fromCharCode(chr3);
        }

    }

    output = Base64._utf8_decode(output);

    return output;

},

// private method for UTF-8 encoding
_utf8_encode : function (string) {
    string = string.replace(/\r\n/g,"\n");
    var utftext = "";

    for (var n = 0; n < string.length; n++) {

        var c = string.charCodeAt(n);

        if (c < 128) {
            utftext += String.fromCharCode(c);
        }
        else if((c > 127) && (c < 2048)) {
            utftext += String.fromCharCode((c >> 6) | 192);
            utftext += String.fromCharCode((c & 63) | 128);
        }
        else {
            utftext += String.fromCharCode((c >> 12) | 224);
            utftext += String.fromCharCode(((c >> 6) & 63) | 128);
            utftext += String.fromCharCode((c & 63) | 128);
        }

    }

    return utftext;
},

// private method for UTF-8 decoding
_utf8_decode : function (utftext) {
    var string = "";
    var i = 0;
    var c = c1 = c2 = 0;

    while ( i < utftext.length ) {

        c = utftext.charCodeAt(i);

        if (c < 128) {
            string += String.fromCharCode(c);
            i++;
        }
        else if((c > 191) && (c < 224)) {
            c2 = utftext.charCodeAt(i+1);
            string += String.fromCharCode(((c & 31) << 6) | (c2 & 63));
            i += 2;
        }
        else {
            c2 = utftext.charCodeAt(i+1);
            c3 = utftext.charCodeAt(i+2);
            string += String.fromCharCode(((c & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63));
            i += 3;
        }

    }

    return string;
}

}