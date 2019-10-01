document.getElementById("convert").onclick = convert;
init();

function init() {
    const Http = new XMLHttpRequest();
    Http.open("GET", "/jwk-to-pem.json");
    Http.send();
    Http.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            document.getElementById("jwk").value = Http.responseText;
        }
    };
}

function convert() {
    const jwk = document.getElementById("jwk").value;
    const Http = new XMLHttpRequest();
    Http.open("POST", "/jwk-to-pem", true);
    Http.setRequestHeader('Content-Type', 'application/json');
    Http.send(jwk);
    Http.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            document.getElementById("pem").value = Http.responseText;
        }
    };
}
