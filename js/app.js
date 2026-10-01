/**************************************************************
 * Initialize Flatpickr in "range" mode
 **************************************************************/
let selectedDateRange = [null, null];
flatpickr("#filterDateRange", {
  mode: "range",
  dateFormat: "Y-m-d",
  onClose: function(selectedDates) {
    selectedDateRange = selectedDates;
    applyFilters();
  }
});

/**************************************************************
 * DOM ELEMENTS
 **************************************************************/
const trufflehogFile = document.getElementById('trufflehogFile');
const sessionFile = document.getElementById('sessionFile'); // for loading session

const toggleRejectedBtn = document.getElementById('toggleRejectedBtn');
const rejectAllBtn = document.getElementById('rejectAllBtn');
const verifyAllBtn = document.getElementById('verifyAllBtn');
const exportVerifiedBtn = document.getElementById('exportVerifiedBtn');
const exportFilteredBtn = document.getElementById('exportFilteredBtn');
const expandAllBtn = document.getElementById('expandAllBtn');
const clearFiltersBtn = document.getElementById('clearFiltersBtn');
const saveSessionBtn = document.getElementById('saveSessionBtn'); // for saving session

// Filter elements
const filterRepository = document.getElementById('filterRepository');
const filterDetector = document.getElementById('filterDetector');
const filterFileName = document.getElementById('filterFileName');
const filterVerified = document.getElementById('filterVerified');
const filterRegex = document.getElementById('filterRegex');
const sortBy = document.getElementById('sortBy');

// Stats elements
const totalFindingsSpan = document.getElementById('totalFindings');
const uniqueRepositoriesSpan = document.getElementById('uniqueRepositories');
const uniqueDetectorsSpan = document.getElementById('uniqueDetectors');
const uniqueFilesSpan = document.getElementById('uniqueFiles');
const uniqueAuthorsSpan = document.getElementById('uniqueAuthors');
const firstSeenSpan = document.getElementById('firstSeen');
const lastSeenSpan = document.getElementById('lastSeen');
const verificationBar = document.getElementById('verificationBar');
const verifiedCountSpan = document.getElementById('verifiedCount');
const unverifiedCountSpan = document.getElementById('unverifiedCount');
const rejectedCountSpan = document.getElementById('rejectedCount');
const filteredCountDisplay = document.getElementById('filteredCountDisplay');

const resultsContainer = document.getElementById('results-container');
const errorLog = document.getElementById('errorLog');

// Full results in memory
let allResults = [];
// Current filtered subset
let currentFilteredResults = [];

// Windowing variables - only one batch rendered at a time
let windowBatchSize = 50;
let currentBatchIndex = 0;
let totalBatches = 0;

// statusesMap: { [uniqueId]: { Verified: bool, Rejected: bool } }
let statusesMap = {};

// Toggling Rejected display
let hideRejected = true;

// Expand/Collapse All toggle
let expandAllState = false;

/**************************************************************
 * RESTORE STATUSES FROM LOCAL STORAGE (if any)
 **************************************************************/
document.addEventListener('DOMContentLoaded', () => {
  try {
    const stored = localStorage.getItem('thStatuses');
    if (stored) {
      statusesMap = JSON.parse(stored);
    }
  } catch (e) {
    console.warn('Error reading localStorage for statuses:', e);
  }
});

/**************************************************************
 * FILE UPLOAD HANDLER (TruffleHog data)
 **************************************************************/
trufflehogFile.addEventListener('change', async (event) => {
  resultsContainer.innerHTML = '';
  errorLog.innerHTML = '';
  allResults = [];
  currentFilteredResults = [];

  // Reset filter dropdowns
  filterRepository.innerHTML = '<option value="">All</option>';
  filterDetector.innerHTML = '<option value="">All</option>';
  filterFileName.innerHTML = '<option value="">All</option>';

  const files = event.target.files;
  const parsePromises = [];

  for (const file of files) {
    const reader = new FileReader();
    const promise = new Promise((resolve) => {
      reader.onload = (e) => {
        const text = e.target.result;
        const lines = text.split('\n').map(l => l.trim()).filter(l => l !== '');

        const repoSet = new Set();
        const detSet = new Set();
        const fileSet = new Set();

        lines.forEach((line, idx) => {
          // skip lines that are not valid JSON
          if (!line.startsWith('{') && !line.startsWith('[')) return;
          try {
            const parsed = JSON.parse(line);

            // Create a short unique ID
            const shortId = 'id' + Math.random().toString(36).substr(2, 6);

            // Restore Verified/Rejected status if it exists
            const oldStatus = statusesMap[shortId] || { Verified: false, Rejected: false };
            parsed.Verified = oldStatus.Verified;
            parsed.Rejected = oldStatus.Rejected;

            parsed._id = shortId;
            parsed._uploadedFile = file.name;
            allResults.push(parsed);

            // Track possible filter values
            const repo = getNestedValue(parsed, 'SourceMetadata.Data.Github.repository');
            if (repo) repoSet.add(repo);

            const det = parsed.DetectorName;
            if (det) detSet.add(det);

            fileSet.add(file.name);

          } catch (err) {
            console.error(`Error parsing JSON in ${file.name} at line ${idx + 1}:`, err);
            const errDiv = document.createElement('div');
            errDiv.classList.add('error-message');
            errDiv.textContent = `Error parsing JSON line ${idx + 1} in ${file.name}: ${err.message}`;
            errorLog.appendChild(errDiv);
          }
        });

        // Update dropdowns
        repoSet.forEach(r => addOptionIfNotExists(filterRepository, r));
        detSet.forEach(d => addOptionIfNotExists(filterDetector, d));
        fileSet.forEach(f => addOptionIfNotExists(filterFileName, f));

        resolve();
      };
      reader.onerror = () => {
        const errDiv = document.createElement('div');
        errDiv.classList.add('error-message');
        errDiv.textContent = `Error reading file: ${file.name}`;
        errorLog.appendChild(errDiv);
        resolve();
      };
      reader.readAsText(file);
    });
    parsePromises.push(promise);
  }

  Promise.all(parsePromises).then(() => {
    updateStats();
    applyFilters();
  });
});

/**************************************************************
 * NEW CODE: LOAD SESSION FILE
 **************************************************************/
sessionFile.addEventListener('change', async (event) => {
  const files = event.target.files;
  if (!files || !files.length) return;

  const file = files[0];
  const reader = new FileReader();
  reader.onload = (e) => {
    try {
      const data = JSON.parse(e.target.result);
      if (!Array.isArray(data)) {
        throw new Error('Session file is not an array of findings.');
      }

      // Reset everything
      allResults = [];
      currentFilteredResults = [];
      resultsContainer.innerHTML = '';
      errorLog.innerHTML = '';

      // Reset filter dropdowns
      filterRepository.innerHTML = '<option value="">All</option>';
      filterDetector.innerHTML = '<option value="">All</option>';
      filterFileName.innerHTML = '<option value="">All</option>';

      // Rebuild local data + statuses
      data.forEach((item) => {
        if (!item._id) {
          // If somehow missing an ID, generate one
          item._id = 'id' + Math.random().toString(36).substr(2, 6);
        }
        statusesMap[item._id] = {
          Verified: !!item.Verified,
          Rejected: !!item.Rejected
        };
        allResults.push(item);

        // Add filter options
        const repo = getNestedValue(item, 'SourceMetadata.Data.Github.repository');
        if (repo) addOptionIfNotExists(filterRepository, repo);

        const det = item.DetectorName;
        if (det) addOptionIfNotExists(filterDetector, det);

        const fName = item._uploadedFile;
        if (fName) addOptionIfNotExists(filterFileName, fName);
      });

      // Store statuses in localStorage
      storeStatuses();

      // Done, update UI
      updateStats();
      applyFilters();
      alert('Session loaded successfully!');
    } catch (err) {
      const errDiv = document.createElement('div');
      errDiv.classList.add('error-message');
      errDiv.textContent = `Error loading session file: ${err.message}`;
      errorLog.appendChild(errDiv);
    }
  };
  reader.readAsText(file);
});
/**************************************************************/

function addOptionIfNotExists(selectEl, value) {
  for (let i = 0; i < selectEl.options.length; i++) {
    if (selectEl.options[i].value === value) return;
  }
  const opt = document.createElement('option');
  opt.value = value;
  opt.textContent = value;
  selectEl.appendChild(opt);
}

/**************************************************************
 * STORE STATUSES
 **************************************************************/
function storeStatuses() {
  try {
    localStorage.setItem('thStatuses', JSON.stringify(statusesMap));
  } catch (e) {
    console.warn('Unable to store statuses:', e);
  }
}

/**************************************************************
 * UPDATE STATS
 **************************************************************/
function updateStats() {
  totalFindingsSpan.textContent = allResults.length;

  const repos = new Set(
    allResults.map(r => getNestedValue(r, 'SourceMetadata.Data.Github.repository')).filter(Boolean)
  );
  uniqueRepositoriesSpan.textContent = repos.size;

  const dets = new Set(allResults.map(r => r.DetectorName).filter(Boolean));
  uniqueDetectorsSpan.textContent = dets.size;

  const files = new Set(allResults.map(r => r._uploadedFile).filter(Boolean));
  uniqueFilesSpan.textContent = files.size;

  const authors = new Set(
    allResults.map(r => getNestedValue(r, 'SourceMetadata.Data.Github.email')).filter(Boolean)
  );
  uniqueAuthorsSpan.textContent = authors.size;

  const timestamps = allResults
    .map(r => getNestedValue(r, 'SourceMetadata.Data.Github.timestamp'))
    .map(ts => ts ? new Date(ts).getTime() : null)
    .filter(x => x && !isNaN(x));
  if (timestamps.length) {
    const min = Math.min(...timestamps);
    const max = Math.max(...timestamps);
    firstSeenSpan.textContent = new Date(min).toLocaleDateString();
    lastSeenSpan.textContent = new Date(max).toLocaleDateString();
  } else {
    firstSeenSpan.textContent = 'N/A';
    lastSeenSpan.textContent = 'N/A';
  }

  const verifiedCount = allResults.filter(r => r.Verified).length;
  const unverifiedCount = allResults.filter(r => !r.Verified).length;
  verifiedCountSpan.textContent = verifiedCount;
  unverifiedCountSpan.textContent = unverifiedCount;

  const rejectedCount = allResults.filter(r => r.Rejected).length;
  rejectedCountSpan.textContent = rejectedCount;

  const total = verifiedCount + unverifiedCount;
  if (total === 0) {
    verificationBar.style.width = '0%';
  } else {
    const pct = (verifiedCount / total) * 100;
    verificationBar.style.width = pct.toFixed(1) + '%';
  }
}

/**************************************************************
 * FILTER & SORT & RENDER
 **************************************************************/
[
  filterRepository, filterDetector, filterFileName, filterVerified, sortBy
].forEach(el => el.addEventListener('change', applyFilters));

// Add regex filter with debouncing and visual feedback
let regexTimeout;
filterRegex.addEventListener('input', () => {
  clearTimeout(regexTimeout);
  regexTimeout = setTimeout(() => {
    applyFilters();
    // Add visual feedback if regex is active
    if (filterRegex.value.trim()) {
      filterRegex.classList.add('active-filter');
    } else {
      filterRegex.classList.remove('active-filter');
    }
  }, 300); // Debounce 300ms
});

function applyFilters() {
  const repoVal = filterRepository.value;
  const detVal = filterDetector.value;
  const fileVal = filterFileName.value;
  const verVal = filterVerified.value;
  const regexVal = filterRegex.value.trim();

  // Compile regex if provided
  let regexPattern = null;
  if (regexVal) {
    try {
      regexPattern = new RegExp(regexVal, 'i'); // Case-insensitive by default
    } catch (e) {
      console.warn('Invalid regex pattern:', e);
      regexPattern = null;
    }
  }

  let [startTime, endTime] = [null, null];
  if (selectedDateRange.length === 2 && selectedDateRange[0] && selectedDateRange[1]) {
    startTime = selectedDateRange[0].getTime();
    endTime = selectedDateRange[1].getTime();
    if (startTime > endTime) {
      const tmp = startTime;
      startTime = endTime;
      endTime = tmp;
    }
  }

  const filtered = allResults.filter(r => {
    // Hide rejected if toggled
    if (hideRejected && r.Rejected) return false;

    let verifiedMatch = true;
    if (verVal === 'true') verifiedMatch = (r.Verified === true);
    if (verVal === 'false') verifiedMatch = (r.Verified === false);

    const repoMatch = !repoVal || (getNestedValue(r, 'SourceMetadata.Data.Github.repository') === repoVal);
    const detMatch = !detVal || (r.DetectorName === detVal);
    const fileMatch = !fileVal || (r._uploadedFile === fileVal);

    const tsStr = getNestedValue(r, 'SourceMetadata.Data.Github.timestamp');
    const tsMs = tsStr ? new Date(tsStr).getTime() : null;
    const dateMatch = (!startTime || (tsMs && tsMs >= startTime)) &&
                      (!endTime || (tsMs && tsMs <= endTime));

    // Regex match on Raw field
    const regexMatch = !regexPattern || (r.Raw && regexPattern.test(r.Raw));

    return verifiedMatch && repoMatch && detMatch && fileMatch && dateMatch && regexMatch;
  });

  // Sort results
  const sortValue = sortBy.value;
  if (sortValue) {
    filtered.sort((a, b) => {
      const getTime = (item) => {
        const t = getNestedValue(item, 'SourceMetadata.Data.Github.timestamp');
        return t ? new Date(t).getTime() : 0;
      };
      const repoA = getNestedValue(a, 'SourceMetadata.Data.Github.repository') || '';
      const repoB = getNestedValue(b, 'SourceMetadata.Data.Github.repository') || '';

      switch (sortValue) {
        case 'dateAsc':    return getTime(a) - getTime(b);
        case 'dateDesc':   return getTime(b) - getTime(a);
        case 'repoAsc':    return repoA.localeCompare(repoB);
        case 'repoDesc':   return repoB.localeCompare(repoA);
        case 'verifiedAsc':
          // move verified to top => so the 'lowest' is unverified
          return (b.Verified ? 1 : 0) - (a.Verified ? 1 : 0);
        case 'verifiedDesc':
          // move unverified to top => so the 'lowest' is verified
          return (a.Verified ? 1 : 0) - (b.Verified ? 1 : 0);
        default:
          return 0;
      }
    });
  }

  currentFilteredResults = filtered;
  currentBatchIndex = 0;
  totalBatches = Math.ceil(filtered.length / windowBatchSize);
  renderCurrentBatch();
  updateFilteredCountDisplay();
}

function updateFilteredCountDisplay() {
  const start = currentBatchIndex * windowBatchSize + 1;
  const end = Math.min((currentBatchIndex + 1) * windowBatchSize, currentFilteredResults.length);
  filteredCountDisplay.textContent = `Showing ${start}-${end} / ${currentFilteredResults.length} filtered (${allResults.length} total)`;
}

function renderCurrentBatch() {
  resultsContainer.innerHTML = '';

  if (!currentFilteredResults.length) {
    resultsContainer.innerHTML = '<p>No results match the current filters.</p>';
    return;
  }

  const start = currentBatchIndex * windowBatchSize;
  const end = Math.min(start + windowBatchSize, currentFilteredResults.length);

  for (let i = start; i < end; i++) {
    const card = createResultCard(currentFilteredResults[i]);
    resultsContainer.appendChild(card);
  }

  addBatchNavigation();
}

function addBatchNavigation() {
  if (totalBatches <= 1) return;

  const nav = document.createElement('div');
  nav.style.cssText = 'display: flex; justify-content: center; gap: 10px; margin-top: 20px; align-items: center;';

  const prevBtn = document.createElement('button');
  prevBtn.className = 'btn btn-info';
  prevBtn.innerHTML = '<i class="bi bi-chevron-left"></i> Previous';
  prevBtn.disabled = currentBatchIndex === 0;
  prevBtn.onclick = () => {
    if (currentBatchIndex > 0) {
      currentBatchIndex--;
      renderCurrentBatch();
      updateFilteredCountDisplay();
      window.scrollTo(0, 0);
    }
  };

  const info = document.createElement('span');
  info.style.cssText = 'color: #666; font-weight: 500;';
  info.textContent = `Page ${currentBatchIndex + 1} of ${totalBatches}`;

  const nextBtn = document.createElement('button');
  nextBtn.className = 'btn btn-info';
  nextBtn.innerHTML = 'Next <i class="bi bi-chevron-right"></i>';
  nextBtn.disabled = currentBatchIndex >= totalBatches - 1;
  nextBtn.onclick = () => {
    if (currentBatchIndex < totalBatches - 1) {
      currentBatchIndex++;
      renderCurrentBatch();
      updateFilteredCountDisplay();
      window.scrollTo(0, 0);
    }
  };

  nav.appendChild(prevBtn);
  nav.appendChild(info);
  nav.appendChild(nextBtn);
  resultsContainer.appendChild(nav);
}

/**************************************************************
 * CREATE RESULT CARD
 **************************************************************/
function createResultCard(result) {
  // By default, all cards are uncollapsed => no "collapsed" class initially
  const container = document.createElement('div');
  container.classList.add('result-container');

  // Header
  const header = document.createElement('div');
  header.classList.add('result-header');

  // Title
  const titleDiv = document.createElement('div');
  titleDiv.classList.add('title');
  titleDiv.textContent = `Finding ID: ${result._id}`;
  header.appendChild(titleDiv);

  // Action buttons (in header)
  const actionsDiv = document.createElement('div');
  actionsDiv.style.display = 'flex';
  actionsDiv.style.gap = '10px';

  const rejectBtn = document.createElement('button');
  rejectBtn.classList.add('btn', 'btn-danger');
  rejectBtn.innerHTML = '<i class="bi bi-x-circle"></i> &nbspReject';
  rejectBtn.title = "Reject this finding";
  rejectBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    result.Rejected = true;
    statusesMap[result._id] = {
      Verified: result.Verified,
      Rejected: true
    };
    storeStatuses();
    updateStats();
    applyFilters();
  });
  actionsDiv.appendChild(rejectBtn);

  const verifyBtn = document.createElement('button');
  verifyBtn.classList.add('btn', 'btn-secondary');
  verifyBtn.innerHTML = '<i class="bi bi-check-circle"></i> &nbspVerify';
  verifyBtn.title = "Mark this finding as verified";
  verifyBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    result.Verified = true;
    statusesMap[result._id] = {
      Verified: true,
      Rejected: result.Rejected
    };
    storeStatuses();
    updateStats();
    applyFilters();
  });
  actionsDiv.appendChild(verifyBtn);

  header.appendChild(actionsDiv);

  header.addEventListener('click', () => {
    container.classList.toggle('collapsed');
  });

  if (expandAllState) {
    container.classList.add('collapsed');
  }

  container.appendChild(header);

  // Collapsed summary line
  const summaryLine = document.createElement('div');
  summaryLine.classList.add('summary-line');
  const linkVal = getNestedValue(result, 'SourceMetadata.Data.Github.link')
    || getNestedValue(result, 'SourceMetadata.Data.Github.file')
    || 'N/A';
  const detVal = result.DetectorName || 'N/A';
  let rawShort = (result.Raw || '').slice(0, 50);
  if (rawShort.length === 50) rawShort += '...';
  summaryLine.innerHTML = `
    <strong>Detector:</strong> ${detVal} &mdash;
    <strong>Path:</strong> ${linkVal} &mdash;
    <strong>Snippet:</strong> ${rawShort}
  `;
  container.appendChild(summaryLine);

  // Full body
  const body = document.createElement('div');
  body.classList.add('result-body');

  // 1) Path
  body.appendChild(createDetail('Path:', linkVal.startsWith('http')
    ? `<a href="${linkVal}" target="_blank">${linkVal}</a>` : linkVal));

  // 2) File
  body.appendChild(createDetail('Uploaded File:', result._uploadedFile || 'N/A'));

  // 3) Repository
  const repoVal = getNestedValue(result, 'SourceMetadata.Data.Github.repository') || 'N/A';
  body.appendChild(createDetail('Repository:', repoVal));

  // 4) Commit
  const commitVal = getNestedValue(result, 'SourceMetadata.Data.Github.commit') || 'N/A';
  body.appendChild(createDetail('Commit:', commitVal));

  // 5) Date
  const timeVal = getNestedValue(result, 'SourceMetadata.Data.Github.timestamp') || 'N/A';
  body.appendChild(createDetail('Date:', timeVal));

  // 6) Author
  const authorVal = getNestedValue(result, 'SourceMetadata.Data.Github.email') || 'N/A';
  body.appendChild(createDetail('Author:', authorVal));

  // 7) Detector
  body.appendChild(createDetail('Detector:', detVal));

  // 8) DetectorDescription
  const descVal = result.DetectorDescription || 'N/A';
  body.appendChild(createDetail('Description:', descVal));

  // Verified
  const verifiedTag = result.Verified
    ? `<i class="bi bi-check-circle-fill"></i> <span class="tag tag-verified">Verified</span>`
    : `<i class="bi bi-x-circle-fill"></i> <span class="tag tag-unverified">Not Verified</span>`;
  body.appendChild(createDetail('Verified:', verifiedTag));

  // Rejected
  const rejectedTag = result.Rejected
    ? `<i class="bi bi-x-circle-fill"></i> <span class="tag tag-rejected">Rejected</span>`
    : 'No';
  body.appendChild(createDetail('Rejected:', rejectedTag));

  // Leaked Info - no expansion needed, scrolling handles it
  const leakedInfoDiv = document.createElement('div');
  leakedInfoDiv.classList.add('leaked-container');
  const rawVal = result.Raw || 'N/A';
  leakedInfoDiv.innerHTML = `<strong>Leaked Information:</strong>\n${rawVal}`;
  body.appendChild(leakedInfoDiv);

  container.appendChild(body);
  return container;
}

function createDetail(label, valueHTML) {
  const div = document.createElement('div');
  div.classList.add('result-detail');
  div.innerHTML = `<strong>${label}</strong> ${valueHTML}`;
  return div;
}

/**************************************************************
 * SHOW/HIDE REJECTED
 **************************************************************/
toggleRejectedBtn.addEventListener('click', () => {
  hideRejected = !hideRejected;
  toggleRejectedBtn.innerHTML = hideRejected
    ? '<i class="bi bi-eye-slash"></i> Hide Rejected'
    : '<i class="bi bi-eye"></i> Show Rejected';
  applyFilters();
});

/**************************************************************
 * MASS UPDATE (Reject or Verify)
 **************************************************************/
rejectAllBtn.addEventListener('click', () => {
  massUpdateFiltered({ Reject: true });
});
verifyAllBtn.addEventListener('click', () => {
  massUpdateFiltered({ Verify: true });
});
function massUpdateFiltered(action) {
  currentFilteredResults.forEach(r => {
    if (action.Reject) r.Rejected = true;
    if (action.Verify) r.Verified = true;
    statusesMap[r._id] = {
      Verified: r.Verified,
      Rejected: r.Rejected
    };
  });
  storeStatuses();
  updateStats();
  applyFilters();
}

/**************************************************************
 * EXPORT RESULTS (Verified, Filtered, etc.)
 **************************************************************/
exportVerifiedBtn.addEventListener('click', () => {
  const verifiedOnly = allResults.filter(r => r.Verified);
  if (!verifiedOnly.length) {
    alert("No verified results to export!");
    return;
  }
  downloadJsonFile(verifiedOnly, "verified_findings.json");
});

exportFilteredBtn.addEventListener('click', () => {
  if (!currentFilteredResults.length) {
    alert("No filtered results to export!");
    return;
  }
  downloadJsonFile(currentFilteredResults, "filtered_findings.json");
});

function downloadJsonFile(dataArray, filename) {
  const blob = new Blob([JSON.stringify(dataArray, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**************************************************************
 * NEW CODE: SAVE CURRENT SESSION
 * Exports the entire 'allResults' array (with statuses)
 **************************************************************/
saveSessionBtn.addEventListener('click', () => {
  if (!allResults.length) {
    alert("No data loaded to save!");
    return;
  }
  // The entire array includes Verified/Rejected flags
  downloadJsonFile(allResults, "session_backup.json");
});

expandAllBtn.addEventListener('click', () => {
  expandAllState = !expandAllState;
  if (expandAllState) {
    expandAllBtn.innerHTML = '<i class="bi bi-arrows-expand"></i> Expand All';
  } else {
    expandAllBtn.innerHTML = '<i class="bi bi-arrows-collapse"></i> Collapse All';
  }
  renderCurrentBatch();
  updateFilteredCountDisplay();
});

/**************************************************************
 * CLEAR ALL FILTERS
 **************************************************************/
clearFiltersBtn.addEventListener('click', () => {
  filterRepository.value = '';
  filterDetector.value = '';
  filterFileName.value = '';
  filterVerified.value = '';
  filterRegex.value = '';
  filterRegex.classList.remove('active-filter'); // Remove visual feedback
  sortBy.value = '';

  selectedDateRange = [null, null];
  const dateInput = document.getElementById('filterDateRange');
  if (dateInput._flatpickr) {
    dateInput._flatpickr.clear();
  }

  applyFilters();
});

/**************************************************************
 * HELPER: getNestedValue
 **************************************************************/
function getNestedValue(obj, path) {
  if (!obj) return undefined;
  return path.split('.').reduce((acc, part) => acc && acc[part], obj);
}
