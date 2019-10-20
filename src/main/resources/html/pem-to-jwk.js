document.getElementById("convert").onclick = convert;
init();

function init() {
    const Http = new XMLHttpRequest();
    Http.open("GET", "/pem-to-jwk.pem");
    Http.send();
    Http.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            document.getElementById("pem").value = Http.responseText;
        }
    };
}

function convert() {
    const pem = document.getElementById("pem").value;
    const Http = new XMLHttpRequest();
    Http.open("POST", "/pem-to-jwk", true);
    Http.setRequestHeader('Content-Type', 'text/plain');
    Http.send(pem);
    Http.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            document.getElementById("jwk").value = Http.responseText;
        }
    };
}
