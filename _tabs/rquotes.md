---
# The default layout is 'page'
icon: fas fa-quote-left
order: 4
---

## Random Quotes Generator.

<div id="quote-box">
  <p id="quote"></p>
  <button onclick="generateQuote()">Generate</button>
</div>

<script>
  const quotes = [
    "The only limit to our realization of tomorrow is our doubts of today.",
    "In the middle of every difficulty lies opportunity.",
    "What we achieve inwardly will change outer reality.",
    "It does not matter how slowly you go as long as you do not stop."
  ];

  function generateQuote() {
    const randomIndex = Math.floor(Math.random() * quotes.length);
    document.getElementById("quote").textContent = quotes[randomIndex];
  }

  generateQuote();
</script>

<style>
#quote-box {
  margin: 2rem auto;
  padding: 1.5rem;
  border: 1px solid var(--color-border-light);
  background-color: var(--color-bg);
  box-shadow: var(--shadow-light);
  border-radius: 0.5rem;
}

button {
  margin-top: 1rem;
  padding: 0.5rem 1rem;
  font-size: 1rem;
  color: var(--color-fg);
  background-color: var(--color-bg-accent);
  border: none;
  border-radius: 0.25rem;
  cursor: pointer;
}

button:hover {
  background-color: var(--color-bg-accent-hover);
}
</style>
