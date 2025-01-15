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
  "He who has a thousand friends has not a friend to spare, and he who has one enemy will meet him everywhere. - Ali ibn Abi Talib",
  "Do not be a slave to others when Allah has created you free. - Ali ibn Abi Talib",
  "The best revenge is to improve yourself. - Ali ibn Abi Talib",
  "The ends justify the means. - Niccolò Machiavelli",
  "It is better to be feared than loved if you cannot be both. - Niccolò Machiavelli",
  "The wise man does at once what the fool does finally. - Niccolò Machiavelli",
  "In the midst of chaos, there is also opportunity. - Sun Tzu",
  "No one can stand up against the authority of truth, and the evil of falsehood is to be fought with enlightening speculation. - Ibn Khaldun",
  "Throughout history many nations have suffered a physical defeat, but that has never marked the end of a nation. But when a nation has become the victim of a psychological defeat, then that marks the end of a nation. - Ibn Khaldun",
  "If you tell a lie big enough and keep repeating it, people will eventually come to believe it. The lie can be maintained only for such time as the State can shield the people from the political, economic and/or military consequences of the lie. It thus becomes vitally important for the State to use all of its powers to repress dissent, for the truth is the mortal enemy of the lie, and thus by extension, the truth is the greatest enemy of the State. - Joseph Goebbels"
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
        background-color: var(--highlight-bg-color);
        box-shadow: var(--language-border-color) 0 0 0 1px;
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
        padding: 0.7rem 2rem;
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
