// Take from Zola repository:
// https://github.com/getzola/zola/blob/master/docs/static/search.js
function debounce(func, wait) {
  var timeout;

  return function () {
    var context = this;
    var args = arguments;
    clearTimeout(timeout);

    timeout = setTimeout(function () {
      timeout = null;
      func.apply(context, args);
    }, wait);
  };
}

// Taken from mdbook
// The strategy is as follows:
// First, assign a value to each word in the document:
//  Words that correspond to search terms (stemmer aware): 40
//  Normal words: 2
//  First word in a sentence: 8
// Then use a sliding window with a constant number of words and count the
// sum of the values of the words within the window. Then use the window that got the
// maximum sum. If there are multiple maximas, then get the last one.
// Enclose the terms in <b>.
function makeTeaser(body, terms) {
  var TERM_WEIGHT = 40;
  var NORMAL_WORD_WEIGHT = 2;
  var FIRST_WORD_WEIGHT = 8;
  var TEASER_MAX_WORDS = 30;

  var stemmedTerms = terms.map(function (w) {
    return elasticlunr.stemmer(w.toLowerCase());
  });
  var termFound = false;
  var index = 0;
  var weighted = []; // contains elements of ["word", weight, index_in_document]

  // split in sentences, then words
  var sentences = body.toLowerCase().split(". ");

  for (var i in sentences) {
    var words = sentences[i].split(" ");
    var value = FIRST_WORD_WEIGHT;

    for (var j in words) {
      var word = words[j];

      if (word.length > 0) {
        for (var k in stemmedTerms) {
          if (elasticlunr.stemmer(word).startsWith(stemmedTerms[k])) {
            value = TERM_WEIGHT;
            termFound = true;
          }
        }
        weighted.push([word, value, index]);
        value = NORMAL_WORD_WEIGHT;
      }

      index += word.length;
      index += 1; // ' ' or '.' if last word in sentence
    }

    index += 1; // because we split at a two-char boundary '. '
  }

  if (weighted.length === 0) {
    return body;
  }

  var windowWeights = [];
  var windowSize = Math.min(weighted.length, TEASER_MAX_WORDS);
  // We add a window with all the weights first
  var curSum = 0;
  for (var i = 0; i < windowSize; i++) {
    curSum += weighted[i][1];
  }
  windowWeights.push(curSum);

  for (var i = 0; i < weighted.length - windowSize; i++) {
    curSum -= weighted[i][1];
    curSum += weighted[i + windowSize][1];
    windowWeights.push(curSum);
  }

  // If we didn't find the term, just pick the first window
  var maxSumIndex = 0;
  if (termFound) {
    var maxFound = 0;
    // backwards
    for (var i = windowWeights.length - 1; i >= 0; i--) {
      if (windowWeights[i] > maxFound) {
        maxFound = windowWeights[i];
        maxSumIndex = i;
      }
    }
  }

  var teaser = [];
  var startIndex = weighted[maxSumIndex][2];
  for (var i = maxSumIndex; i < maxSumIndex + windowSize; i++) {
    var word = weighted[i];
    if (startIndex < word[2]) {
      // missing text from index to start of `word`
      teaser.push(body.substring(startIndex, word[2]));
      startIndex = word[2];
    }

    // add <em/> around search terms
    if (word[1] === TERM_WEIGHT) {
      teaser.push("<b>");
    }
    startIndex = word[2] + word[0].length;
    teaser.push(body.substring(word[2], startIndex));

    if (word[1] === TERM_WEIGHT) {
      teaser.push("</b>");
    }
  }
  teaser.push("…");
  return teaser.join("");
}

function formatSearchResultItem(item, terms) {
  return (
    '<div class="search-results__item">' +
    `<a href="${item.ref}">${item.doc.title}</a>` +
    `<div>${makeTeaser(item.doc.body, terms)}</div>` +
    "</div>"
  );
}

function initSearch() {
  var $searchInput = document.getElementById("search");
  var $searchResults = document.querySelector(".search-results");
  var $searchResultsItems = document.querySelector(".search-results__items");
  var MAX_ITEMS = 10;

  var options = {
    bool: "AND",
    fields: {
      title: { boost: 2 },
      body: { boost: 1 },
    },
  };
  var currentTerm = "";
  var index;

  const initIndex = function () {
    if (index === undefined) {
      // Get the base path by looking for the first path segment
      const pathParts = window.location.pathname.split("/");
      const basePath = pathParts[1] ? `/${pathParts[1]}` : "";
      const indexPath = `${basePath}/search_index.en.json`;

      // Try fetching the search index file from the base path
      // and if that fails, try fetching it from the root path
      index = fetch(indexPath)
        .then((response) => {
          if (!response.ok && response.status === 404) {
            // If base path fails, try root path
            return fetch("/search_index.en.json");
          }
          return response;
        })
        .then((response) => {
          if (!response.ok && response.status === 404) {
            // If both paths fail
            console.warn(
              "Search index not found at either the base or root path.",
            );
            return null;
          }
          return response.json();
        })
        .then((data) => {
          if (data) {
            return elasticlunr.Index.load(data);
          }
          return null;
        })
        .catch((error) => {
          console.error("Error loading search index:", error);
          throw error;
        });
    }

    return index;
  };

  $searchInput.addEventListener(
    "keyup",
    debounce(async function () {
      var term = $searchInput.value.trim();
      if (term === currentTerm) {
        return;
      }
      $searchResults.style.display = term === "" ? "none" : "block";
      $searchResultsItems.innerHTML = "";
      currentTerm = term;
      if (term === "") {
        return;
      }

      var results = (await initIndex()).search(term, options);
      if (results.length === 0) {
        $searchResults.style.display = "none";
        return;
      }

      for (var i = 0; i < Math.min(results.length, MAX_ITEMS); i++) {
        var item = document.createElement("li");
        item.innerHTML = formatSearchResultItem(results[i], term.split(" "));
        $searchResultsItems.appendChild(item);
      }
    }, 150),
  );

  // exit search on ESC key and move cursor out of search results
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") {
      $searchResults.style.display = "none";
      // clear search query to go back to placeholder
      $searchInput.value = "";
      $searchInput.blur();
    }
  });

  // event listener for `/` to move cursor to search input
  document.addEventListener("keydown", function (e) {
    if (e.key === "/") {
      // don't have input be `/`
      e.preventDefault();
      $searchInput.focus();
    }
  });

  // on enter event immediately display results
  $searchInput.addEventListener("keydown", function (e) {
    if (e.key === "Enter") {
      $searchResults.style.display = "block";
    }
  });

  window.addEventListener("click", function (e) {
    if (
      $searchResults.style.display == "block" &&
      !$searchResults.contains(e.target)
    ) {
      $searchResults.style.display = "none";
    }
  });
}

if (
  document.readyState === "complete" ||
  (document.readyState !== "loading" && !document.documentElement.doScroll)
) {
  initSearch();
} else {
  document.addEventListener("DOMContentLoaded", initSearch);
}


document.addEventListener("DOMContentLoaded", function () {
  const titles = document.querySelectorAll('.hack h1');
  titles.forEach(title => {
    const text = title.innerText || title.textContent;
    const cleanText = text.trim();
    const equalsLine = '='.repeat(cleanText.length);
    title.setAttribute('data-equals', equalsLine);
  });
});

document.addEventListener("DOMContentLoaded", function () {
  const title = document.querySelector("h1, .site-title, header h1, .hack h1");
  if (!title) return;
  if (!title.textContent.trim()) return;

  // Every h1 (homepage site title and post titles) picks a random intro
  // animation on each load. On Arabic posts (article.rtl-post) the
  // typewriter is swapped for rtlReveal — the clip-path right-to-left
  // reveal that keeps Arabic letter shaping intact. The other two
  // animations work on either direction since bootPrint only touches
  // opacity/text-shadow and glitchReveal substitutes ASCII chars that
  // don't break the final shaped text once they lock in.
  const isRtlPost = !!document.querySelector("article.rtl-post");
  const animations = [
    glitchReveal,
    bootPrint,
    isRtlPost ? rtlReveal : typewriter,
  ];
  animations[Math.floor(Math.random() * animations.length)](title);

  // Glitch/scramble reveal: each character cycles through ASCII alphanumerics
  // with per-character random lock-in times distributed across ~1200ms.
  // Spaces stay as spaces so word boundaries remain visible. Monospace font
  // keeps widths constant — no reflow.
  function glitchReveal(t) {
    const finalText = t.textContent;
    const glitchChars =
      "ABCDEGHIJKLMNOPQRSTVWXYZabcdefghijlmnoprstuvwxyz0123456789أ ب ت ج ح خ د ذ ر ز س ص ط ع ف ق ك ل م ن ه و ي";
    const duration = 1400;
    // Re-randomize chars only every TICK_MS instead of every animation frame
    // (~60fps), so each random char stays on screen long enough to be read
    // before morphing to the next. Lower = faster scramble, higher = chunkier.
    const TICK_MS = 40;
    const lockInTimes = Array.from(finalText, () => Math.random() * duration * 0.85);
    const start = performance.now();
    let lastTick = -TICK_MS;
    (function frame() {
      const now = performance.now() - start;
      if (now - lastTick >= TICK_MS) {
        lastTick = now;
        let out = "";
        for (let i = 0; i < finalText.length; i++) {
          const ch = finalText[i];
          if (ch === " " || now >= lockInTimes[i]) {
            out += ch;
          } else {
            out += glitchChars[Math.floor(Math.random() * glitchChars.length)];
          }
        }
        t.textContent = out;
      }
      if (now < duration) {
        requestAnimationFrame(frame);
      } else {
        t.textContent = finalText;
      }
    })();
  }

  // Boot print: CRT-style power-up flicker on the text only. The title text
  // is wrapped in an inner span and the opacity/glow are applied to that
  // span — the h1 itself stays at full opacity so its `::after` underline
  // (data-equals `=====`) stays visible throughout the flicker. Opacity on
  // a parent transparency-blends pseudo-elements too, which is why this
  // can't just be applied to the h1.
  function bootPrint(t) {
    const finalText = t.textContent;
    t.textContent = "";
    const inner = document.createElement("span");
    inner.textContent = finalText;
    t.appendChild(inner);

    inner.style.opacity = "0";
    const flicker = [
      { delay: 180, op: "1", glow: "0 0 1px #2effcb" },
      { delay: 110, op: "0", glow: ""                 },
      { delay: 150, op: "1", glow: "0 0 3px #2effcb" },
      { delay: 200, op: "0", glow: ""                 },
      { delay: 150, op: "1", glow: "0 0 2px #2effcb" },
      { delay: 450, op: "1", glow: ""                 },
    ];
    let total = 0;
    flicker.forEach(step => {
      total += step.delay;
      setTimeout(() => {
        inner.style.opacity = step.op;
        inner.style.textShadow = step.glow;
      }, total);
    });
  }

  // Typewriter: clear the title and insert each character before a blinking
  // cursor span. The data-equals underline (sized at page load to the full
  // title) is revealed gradually as the h1 grows to fit each new char.
  function typewriter(t) {
    const finalText = t.textContent;
    t.textContent = "";
    const cursor = document.createElement("span");
    cursor.textContent = "|";
    cursor.style.color = "#2effcb";
    cursor.style.fontFamily = "inherit";
    t.appendChild(cursor);
    let i = 0;
    const typeInterval = setInterval(() => {
      if (i < finalText.length) {
        t.insertBefore(document.createTextNode(finalText.charAt(i)), cursor);
        i++;
      } else {
        clearInterval(typeInterval);
        cursor.style.animation = "blink 1s step-end infinite";
      }
    }, 65);
  }

  // RTL reveal (Arabic posts): per-character DOM insertion can't work here
  // — bidi reorders mixed Latin/Arabic runs on every insert (title "jumps"
  // into chunks), and reverse insertion would break Arabic letter joining.
  // Render the full title once and animate a clip-path that exposes it from
  // right to left: `inset(0 0 0 100%)` collapses the visible rect to the
  // right edge, animating left inset down to 0 grows it leftward one
  // char-width per step. An absolutely-positioned cursor tracks the leading
  // edge by animating its `right` value with the matching steps() cadence.
  function rtlReveal(t) {
    const finalText = t.textContent.trim();
    t.textContent = "";
    const N = finalText.length;
    const duration = N * 65;

    const textSpan = document.createElement("span");
    textSpan.textContent = finalText;
    textSpan.style.display = "inline-block";
    textSpan.style.clipPath = "inset(0 0 0 100%)";
    textSpan.style.transition = "clip-path " + duration + "ms steps(" + N + ")";
    t.appendChild(textSpan);

    const cursor = document.createElement("span");
    cursor.textContent = "|";
    cursor.style.color = "#2effcb";
    cursor.style.fontFamily = "inherit";
    cursor.style.position = "absolute";
    cursor.style.right = "0";
    cursor.style.animation = "blink 1s step-end infinite";
    t.appendChild(cursor);

    requestAnimationFrame(() => {
      const fullWidth = textSpan.offsetWidth;
      cursor.style.transition = "right " + duration + "ms steps(" + N + ")";
      requestAnimationFrame(() => {
        textSpan.style.clipPath = "inset(0 0 0 0)";
        cursor.style.right = fullWidth + "px";
      });
    });
  }
});

// Blinking animation
const style = document.createElement('style');
style.textContent = `
  @keyframes blink {
    0%, 100% { opacity: 1; }
    50% { opacity: 0; }
  }
`;

document.head.appendChild(style);