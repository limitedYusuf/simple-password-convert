const { createApp } = Vue;
createApp({
  data() {
    return {
      input: "",
      selected: "md5",
      tempSelected: "md5",
      showModal: false,
      output: "",
      error: "",
      loading: false,
      copied: false,
      modalAnimClass: "scale-90 opacity-0",
      activeTab: "encrypt",
      algorithms: [
        { value: "md5", label: "MD5" },
        { value: "sha1", label: "SHA-1" },
        { value: "sha224", label: "SHA-224" },
        { value: "sha256", label: "SHA-256" },
        { value: "sha384", label: "SHA-384" },
        { value: "sha512", label: "SHA-512" },
        { value: "sha3-224", label: "SHA3-224" },
        { value: "sha3-256", label: "SHA3-256" },
        { value: "sha3-384", label: "SHA3-384" },
        { value: "sha3-512", label: "SHA3-512" },
        { value: "ripemd160", label: "RIPEMD-160" },
        { value: "whirlpool", label: "Whirlpool" },
        { value: "bcrypt", label: "bcrypt" },
        { value: "base64", label: "Base64 Encode" },
        { value: "base64decode", label: "Base64 Decode" },
        { value: "hex", label: "Hex Encode" },
        { value: "hexdecode", label: "Hex Decode" },
        { value: "rot13", label: "ROT13" },
        { value: "crc32", label: "CRC32" },
        { value: "crc16", label: "CRC16" },
        { value: "adler32", label: "Adler-32" },
        { value: "hmac-md5", label: "HMAC-MD5" },
        { value: "hmac-sha1", label: "HMAC-SHA1" },
        { value: "hmac-sha256", label: "HMAC-SHA256" },
        { value: "hmac-sha512", label: "HMAC-SHA512" },
        { value: "pbkdf2", label: "PBKDF2" },
        { value: "argon2", label: "Argon2" },
        { value: "aes", label: "AES Encrypt" },
        { value: "aes-decrypt", label: "AES Decrypt" },
        { value: "des", label: "DES Encrypt" },
        { value: "md4", label: "MD4" },
        { value: "md2", label: "MD2" },
        { value: "sha512-224", label: "SHA-512/224" },
        { value: "sha512-256", label: "SHA-512/256" },
        { value: "sha1-base64", label: "SHA-1 (Base64)" },
        { value: "sha256-base64", label: "SHA-256 (Base64)" },
        { value: "sha512-base64", label: "SHA-512 (Base64)" },
        { value: "sha1-hex", label: "SHA-1 (Hex)" },
        { value: "sha256-hex", label: "SHA-256 (Hex)" },
        { value: "sha512-hex", label: "SHA-512 (Hex)" },
        { value: "sha3-512-224", label: "SHA3-512/224" },
        { value: "sha3-512-256", label: "SHA3-512/256" },
        { value: "sha3-512-384", label: "SHA3-512/384" },
        { value: "sha3-512-512", label: "SHA3-512/512" },
        { value: "keccak256", label: "Keccak-256" },
        { value: "keccak512", label: "Keccak-512" },
        { value: "xxhash32", label: "xxHash32" },
        { value: "xxhash64", label: "xxHash64" },
        { value: "murmurhash3", label: "MurmurHash3" },
        { value: "blake2b", label: "BLAKE2b" },
        { value: "blake2s", label: "BLAKE2s" },
      ],
      encryptAlgos: [
        "md5",
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha3-224",
        "sha3-256",
        "sha3-384",
        "sha3-512",
        "ripemd160",
        "whirlpool",
        "bcrypt",
        "base64",
        "hex",
        "rot13",
        "crc32",
        "crc16",
        "adler32",
        "hmac-md5",
        "hmac-sha1",
        "hmac-sha256",
        "hmac-sha512",
        "pbkdf2",
        "argon2",
        "aes",
        "des",
        "md4",
        "md2",
        "sha512-224",
        "sha512-256",
        "sha1-base64",
        "sha256-base64",
        "sha512-base64",
        "sha1-hex",
        "sha256-hex",
        "sha512-hex",
        "sha3-512-224",
        "sha3-512-256",
        "sha3-512-384",
        "sha3-512-512",
        "keccak256",
        "keccak512",
        "xxhash32",
        "xxhash64",
        "murmurhash3",
        "blake2b",
        "blake2s",
      ],
      decryptAlgos: ["base64decode", "hexdecode", "aes-decrypt"],
    };
  },
  computed: {
    selectedLabel() {
      const found = this.algorithms.find((a) => a.value === this.selected);
      return found ? found.label : this.selected;
    },
    filteredAlgorithms() {
      return this.algorithms.filter((a) =>
        this.activeTab === "encrypt"
          ? this.encryptAlgos.includes(a.value)
          : this.decryptAlgos.includes(a.value)
      );
    },
  },
  watch: {
    showModal(val) {
      if (val) {
        setTimeout(() => {
          this.modalAnimClass = "scale-100 opacity-100";
        }, 10);
      } else {
        this.modalAnimClass = "scale-90 opacity-0";
      }
    },
    activeTab(val) {
      const first = this.filteredAlgorithms[0];
      if (first) {
        this.selected = first.value;
        this.tempSelected = first.value;
      }
    },
  },
  mounted() {
    setTimeout(() => {
      const el = document.querySelector(".animate-fadein");
      if (el) el.classList.add("opacity-100");
    }, 100);
  },
  methods: {
    tabClass(tab) {
      return {
        "bg-blue-600 text-white": this.activeTab === tab,
        "bg-gray-200 text-gray-800": this.activeTab !== tab,
      };
    },
    closeModal() {
      this.showModal = false;
    },
    async convert() {
      this.output = "";
      this.error = "";
      this.copied = false;
      this.loading = true;
      const text = this.input;
      const algo = this.selected;
      let result = "";
      try {
        if (algo === "md5") {
          result = window.CryptoJS.MD5(text).toString();
        } else if (algo === "sha1") {
          result = window.CryptoJS.SHA1(text).toString();
        } else if (algo === "sha224") {
          result = window.CryptoJS.SHA224(text).toString();
        } else if (algo === "sha256") {
          result = window.CryptoJS.SHA256(text).toString();
        } else if (algo === "sha384") {
          result = window.CryptoJS.SHA384(text).toString();
        } else if (algo === "sha512") {
          result = window.CryptoJS.SHA512(text).toString();
        } else if (algo === "sha3-224") {
          result = window.CryptoJS.SHA3(text, {
            outputLength: 224,
          }).toString();
        } else if (algo === "sha3-256") {
          result = window.CryptoJS.SHA3(text, {
            outputLength: 256,
          }).toString();
        } else if (algo === "sha3-384") {
          result = window.CryptoJS.SHA3(text, {
            outputLength: 384,
          }).toString();
        } else if (algo === "sha3-512") {
          result = window.CryptoJS.SHA3(text, {
            outputLength: 512,
          }).toString();
        } else if (algo === "ripemd160") {
          result = window.CryptoJS.RIPEMD160(text).toString();
        } else if (algo === "whirlpool") {
          result = "Not supported in browser";
        } else if (algo === "bcrypt") {
          if (window.dcodeIO && window.dcodeIO.bcrypt) {
            result = await window.dcodeIO.bcrypt.hash(text, 10);
          } else {
            throw new Error("bcrypt library not loaded");
          }
        } else if (algo === "base64") {
          result = btoa(unescape(encodeURIComponent(text)));
        } else if (algo === "base64decode") {
          try {
            result = decodeURIComponent(escape(atob(text)));
          } catch {
            throw new Error("Invalid Base64");
          }
        } else if (algo === "hex") {
          result = Array.from(text)
            .map((c) => c.charCodeAt(0).toString(16).padStart(2, "0"))
            .join("");
        } else if (algo === "hexdecode") {
          try {
            result = text
              .match(/.{1,2}/g)
              .map((b) => String.fromCharCode(parseInt(b, 16)))
              .join("");
          } catch {
            throw new Error("Invalid Hex");
          }
        } else if (algo === "rot13") {
          result = text.replace(/[a-zA-Z]/g, (c) =>
            String.fromCharCode(
              (c <= "Z" ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26
            )
          );
        } else if (algo === "crc32") {
          result = window.CRC32.str(text).toString(16);
        } else if (algo === "crc16") {
          result = window.crc16(text);
        } else if (algo === "adler32") {
          result = window.adler32(text);
        } else if (algo === "hmac-md5") {
          result = window.CryptoJS.HmacMD5(text, "secret").toString();
        } else if (algo === "hmac-sha1") {
          result = window.CryptoJS.HmacSHA1(text, "secret").toString();
        } else if (algo === "hmac-sha256") {
          result = window.CryptoJS.HmacSHA256(text, "secret").toString();
        } else if (algo === "hmac-sha512") {
          result = window.CryptoJS.HmacSHA512(text, "secret").toString();
        } else if (algo === "pbkdf2") {
          result = window.CryptoJS.PBKDF2(text, "salt", {
            keySize: 256 / 32,
          }).toString();
        } else if (algo === "argon2") {
          if (window.argon2 && window.argon2.hash) {
            const hash = await window.argon2.hash({
              pass: text,
              salt: "somesalt",
            });
            result = hash.encoded || hash.hashHex || JSON.stringify(hash);
          } else {
            throw new Error("argon2 library not loaded");
          }
        } else if (algo === "aes") {
          result = window.CryptoJS.AES.encrypt(text, "secret").toString();
        } else if (algo === "aes-decrypt") {
          try {
            result = window.CryptoJS.AES.decrypt(text, "secret").toString(
              window.CryptoJS.enc.Utf8
            );
            if (!result) throw new Error("Invalid AES");
          } catch {
            throw new Error("Invalid AES");
          }
        } else if (algo === "des") {
          result = window.CryptoJS.DES.encrypt(text, "secret").toString();
        } else if (algo === "md4") {
          result = "Not supported in browser";
        } else if (algo === "md2") {
          result = "Not supported in browser";
        } else if (algo === "sha512-224") {
          result = "Not supported in browser";
        } else if (algo === "sha512-256") {
          result = "Not supported in browser";
        } else if (algo === "sha1-base64") {
          result = btoa(
            window.CryptoJS.SHA1(text).toString(window.CryptoJS.enc.Latin1)
          );
        } else if (algo === "sha256-base64") {
          result = btoa(
            window.CryptoJS.SHA256(text).toString(window.CryptoJS.enc.Latin1)
          );
        } else if (algo === "sha512-base64") {
          result = btoa(
            window.CryptoJS.SHA512(text).toString(window.CryptoJS.enc.Latin1)
          );
        } else if (algo === "sha1-hex") {
          result = window.CryptoJS.SHA1(text).toString(window.CryptoJS.enc.Hex);
        } else if (algo === "sha256-hex") {
          result = window.CryptoJS.SHA256(text).toString(
            window.CryptoJS.enc.Hex
          );
        } else if (algo === "sha512-hex") {
          result = window.CryptoJS.SHA512(text).toString(
            window.CryptoJS.enc.Hex
          );
        } else if (algo === "sha3-512-224") {
          result = window.CryptoJS.SHA3(text, {
            outputLength: 224,
          }).toString();
        } else if (algo === "sha3-512-256") {
          result = window.CryptoJS.SHA3(text, {
            outputLength: 256,
          }).toString();
        } else if (algo === "sha3-512-384") {
          result = window.CryptoJS.SHA3(text, {
            outputLength: 384,
          }).toString();
        } else if (algo === "sha3-512-512") {
          result = window.CryptoJS.SHA3(text, {
            outputLength: 512,
          }).toString();
        } else if (algo === "keccak256") {
          result = "Not supported in browser";
        } else if (algo === "keccak512") {
          result = "Not supported in browser";
        } else if (algo === "xxhash32") {
          result = "Not supported in browser";
        } else if (algo === "xxhash64") {
          result = "Not supported in browser";
        } else if (algo === "murmurhash3") {
          result = "Not supported in browser";
        } else if (algo === "blake2b") {
          result = "Not supported in browser";
        } else if (algo === "blake2s") {
          result = "Not supported in browser";
        } else {
          throw new Error("Not implemented");
        }
        this.output = result;
      } catch (e) {
        this.error = e.message || "Error";
      }
      this.loading = false;
    },
    async copyResult() {
      if (!this.output) return;
      try {
        await navigator.clipboard.writeText(this.output);
        this.copied = true;
        setTimeout(() => (this.copied = false), 1200);
      } catch {
        this.copied = false;
      }
    },
    confirmSelect() {
      this.selected = this.tempSelected;
      this.showModal = false;
    },
  },
}).mount("#app");
