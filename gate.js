// Gerbang login bersama — sertakan <script src="gate.js"></script> di halaman ber-body class="locked"
(function(){
  var HASH="19b7098964c45fc7c70b3b37f8fd4ed647099ac71a7ab8bf87731415bd8ca06d";
  var CARD='<div class="lg-card"><img src="logo.svg" alt="Lambang Jawa Barat"><h2>Analisis Ekonomi Jawa Barat</h2><p>Akses terbatas \u2014 masukkan kredensial Anda</p><form id="lg-form"><label for="lg-user">Username</label><input id="lg-user" autocomplete="username" required><label for="lg-pass">Password</label><input id="lg-pass" type="password" autocomplete="current-password" required><button type="submit">Masuk \u2192</button><div class="lg-err" id="lg-err"></div></form></div>';

  function sha256js(ascii){
    function rr(v,a){return(v>>>a)|(v<<(32-a));}
    var mathPow=Math.pow,maxWord=mathPow(2,32),result='',words=[],asciiBitLength=ascii.length*8;
    var hash=sha256js.h=sha256js.h||[],k=sha256js.k=sha256js.k||[],primeCounter=k.length,isComposite={};
    for(var candidate=2;primeCounter<64;candidate++){
      if(!isComposite[candidate]){
        for(var i=0;i<313;i+=candidate)isComposite[i]=candidate;
        hash[primeCounter]=(mathPow(candidate,0.5)*maxWord)|0;
        k[primeCounter++]=(mathPow(candidate,1/3)*maxWord)|0;
      }
    }
    ascii+='\x80';
    while(ascii.length%64-56)ascii+='\x00';
    for(i=0;i<ascii.length;i++){
      var j=ascii.charCodeAt(i);
      if(j>>8)return'';
      words[i>>2]|=j<<((3-i)%4)*8;
    }
    words[words.length]=(asciiBitLength/maxWord)|0;
    words[words.length]=asciiBitLength;
    for(j=0;j<words.length;){
      var w=words.slice(j,j+=16),oldHash=hash;
      hash=hash.slice(0,8);
      for(i=0;i<64;i++){
        var w15=w[i-15],w2=w[i-2];
        var a=hash[0],e=hash[4];
        var temp1=hash[7]+(rr(e,6)^rr(e,11)^rr(e,25))+((e&hash[5])^((~e)&hash[6]))+k[i]+(w[i]=(i<16)?w[i]:(w[i-16]+(rr(w15,7)^rr(w15,18)^(w15>>>3))+w[i-7]+(rr(w2,17)^rr(w2,19)^(w2>>>10)))|0);
        var temp2=(rr(a,2)^rr(a,13)^rr(a,22))+((a&hash[1])^(a&hash[2])^(hash[1]&hash[2]));
        hash=[(temp1+temp2)|0].concat(hash);
        hash[4]=(hash[4]+temp1)|0;
      }
      for(i=0;i<8;i++)hash[i]=(hash[i]+oldHash[i])|0;
    }
    for(i=0;i<8;i++)for(j=3;j+1;j--){
      var b=(hash[i]>>(j*8))&255;
      result+=((b>>4).toString(16))+((b&15).toString(16));
    }
    return result;
  }

  function digest(text){
    if(window.crypto&&crypto.subtle&&crypto.subtle.digest){
      return crypto.subtle.digest('SHA-256',new TextEncoder().encode(text))
        .then(function(buf){return Array.prototype.map.call(new Uint8Array(buf),function(x){return x.toString(16).padStart(2,'0');}).join('');})
        .catch(function(){return sha256js(text);});
    }
    return Promise.resolve(sha256js(text));
  }

  function ready(fn){ if(document.readyState!=='loading') fn(); else document.addEventListener('DOMContentLoaded',fn); }

  ready(function(){
    var gate=document.createElement('div');
    gate.id='login-gate'; gate.innerHTML=CARD;
    document.body.appendChild(gate);
    var errBox=gate.querySelector('#lg-err');
    function lock(){gate.hidden=false;gate.style.display='flex';document.body.classList.add('locked');}
    function unlock(){gate.hidden=true;gate.style.display='none';document.body.classList.remove('locked');}
    function showErr(m){errBox.textContent=m;errBox.style.display='block';}
    var saved=null; try{saved=sessionStorage.getItem('jbr_auth');}catch(e){}
    if(saved===HASH){unlock();}else{lock();}
    gate.querySelector('#lg-form').addEventListener('submit',function(e){
      e.preventDefault();
      var u=gate.querySelector('#lg-user').value.trim();
      var pw=gate.querySelector('#lg-pass').value;
      digest(u+':'+pw).then(function(d){
        if(d===HASH){try{sessionStorage.setItem('jbr_auth',d);}catch(err){} unlock();}
        else{showErr('Username atau password salah.');gate.querySelector('#lg-pass').value='';}
      }).catch(function(){showErr('Kendala teknis saat verifikasi. Muat ulang dan coba lagi.');});
    });
  });

  window.jbrLogout=function(){try{sessionStorage.removeItem('jbr_auth');}catch(e){} location.href='index.html';};
})();
