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
        margin: 2.5rem auto;
        padding: 1.5rem;
        border: 1px solid var(--color-border-dark, #222222);
        background-color: var(--color-bg, #2c2c2c);
        box-shadow: var(--shadow-light, 0px 2px 4px rgba(0, 0, 0, 0.5));
        border-radius: 0.8rem;
        text-align: center;
      }

      #quote {
        font-size: 1.25rem;
        font-style: italic;
        color: var(--color-fg-light, #f5f5f5);
        margin-bottom: 1rem;
      }

      button {
        display: inline-block;
        margin-top: 1rem;
        padding: 1rem 2rem;
        font-size: 1rem;
        color: var(--color-fg-light, #fff);
        background-color: var(--color-bg-dark, #2c2c2c);
        border: 2px solid var(--color-border-dark, #666);
        border-radius: 0.8rem;
        cursor: pointer;
        text-align: center;
        text-decoration: none;
        box-shadow: var(--shadow-dark, 0px 2px 4px rgba(0, 0, 0, 0.8));
        transition: background-color 0.3s ease, transform 0.4s ease;
      }

      button:hover {
        background-color: var(--color-bg-hover, #555);
        transform: scale(1.05);
      }

      button:active {
        transform: scale(1);
      }
</style>
