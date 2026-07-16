function render() {
  const frag = location.hash;
  document.getElementById("out").innerHTML = frag; // sink: DOM XSS
}
