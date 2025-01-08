---
# The default layout is 'page'
icon: fas fa-quote-left
order: 4
---

## RQUOTES - Random Quotes Generator.

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
  border: 1px solid var(--color-border-light, #ddd); 
  background-color: var(--color-bg, #f9f9f9); 
  box-shadow: var(--shadow-light, 0px 2px 4px rgba(0, 0, 0, 0.1));
  border-radius: 0.5rem;
  text-align: center;
}

#quote {
  font-size: 1.25rem;
  font-style: italic;
  color: var(--color-fg, #333); 
  margin-bottom: 1rem;
}

button {
  display: inline-block;
  margin-top: 1rem;
  padding: 1rem 2rem;
  font-size: 1rem;
  color: var(--color-fg, #fff);
  background-color: #007BFF; 
  border: 2px solid #0056b3; 
  border-radius: 0.8rem; 
  cursor: pointer;
  text-align: center;
  text-decoration: none;
  box-shadow: var(--shadow-light, 0px 2px 4px rgba(0, 0, 0, 0.1));
  transition: background-color 0.3s ease, transform 0.4s ease;
}

button:hover {
  background-color: #0056b3; /* Darker blue for hover */
  transform: scale(1.05);
}

button:active {
  transform: scale(1);
}
</style>
