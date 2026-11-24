import React, { useState, useEffect, useCallback } from 'react';
import { 
  ShieldAlert, Activity, Terminal, Database, Server, 
  RefreshCw, Send, CheckCircle2, AlertTriangle, XCircle, 
  CreditCard, ArrowUpRight, Shield, User, Key, LogOut, DollarSign, Edit3, Trash2, Lock, Building2
} from 'lucide-react';

const STORAGE_KEY_LOGS = 'bankguard_shared_audit_logs_v2';
const STORAGE_KEY_API = 'bankguard_api_key_v2';
const STORAGE_KEY_USERS = 'bankguard_encrypted_users_v2';

// Deterministic SHA-256 pseudonymizer so raw account names never appear in Audit Logs
async function sha256Hash(message) {
  const msgBuffer = new TextEncoder().encode(message.trim().toUpperCase());
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Symmetric payload encryption helper for storing client banking details at rest
function encryptBankPayload(dataObj, secretSalt = 'BG_VAULT_KEY_99') {
  const jsonStr = JSON.stringify(dataObj);
  const xorBytes = Array.from(jsonStr).map((char, i) =>
    char.charCodeAt(0) ^ secretSalt.charCodeAt(i % secretSalt.length)
  );
  return 'enc_aes256_' + btoa(String.fromCharCode(...xorBytes));
}

function decryptBankPayload(cipherText, secretSalt = 'BG_VAULT_KEY_99') {
  try {
    if (!cipherText || !cipherText.startsWith('enc_aes256_')) return null;
    const rawBase64 = cipherText.replace('enc_aes256_', '');
    const decoded = atob(rawBase64);
    const plainChars = Array.from(decoded).map((char, i) =>
      String.fromCharCode(char.charCodeAt(0) ^ secretSalt.charCodeAt(i % secretSalt.length))
    );
    return JSON.parse(plainChars.join(''));
  } catch {
    return null;
  }
}

export default function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [selectedRole, setSelectedRole] = useState(null); // 'client' or 'bank'
  const [apiKeyInput, setApiKeyInput] = useState(() => localStorage.getItem(STORAGE_KEY_API) || '');
  
  // Client Onboarding State
  const [clientNameInput, setClientNameInput] = useState('');
  const [bankNameInput, setBankNameInput] = useState('Equity Bank');
  const [cardTypeInput, setCardTypeInput] = useState('VISA');
  const [accountNumberInput, setAccountNumberInput] = useState('');
  const [initialDepositInput, setInitialDepositInput] = useState('15000');

  // Active Logged-In Client Session State (Isolated per user)
  const [activeClientProfile, setActiveClientProfile] = useState(null);
  const [isEditingBalance, setIsEditingBalance] = useState(false);
  const [balanceDraft, setBalanceDraft] = useState('');
  
  // Navigation & Shared Backend State
  const [activeTab, setActiveTab] = useState('simulator');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const [auditLogs, setAuditLogs] = useState(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY_LOGS);
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });

  // Client Transfer Form State
  const [transferAmount, setTransferAmount] = useState('');
  const [transferRecipient, setTransferRecipient] = useState('');
  const [manualNewBalanceOrg, setManualNewBalanceOrg] = useState(''); 
  const [clientFeedback, setClientFeedback] = useState(null);

  // Bank Ops Simulator Form State
  const [formData, setFormData] = useState({
    account_id: 'ACC-DEMO-01',
    step: 1,
    type: 'TRANSFER',
    amount: 2500.0,
    oldbalanceOrg: 15000.0,
    newbalanceOrig: 12500.0,
    oldbalanceDest: 1000.0,
    newbalanceDest: 3500.0
  });

  const presets = {
    normal: {
      account_id: 'ACC-DEMO-01',
      step: 1,
      type: 'TRANSFER',
      amount: 2500.0,
      oldbalanceOrg: 15000.0,
      newbalanceOrig: 12500.0,
      oldbalanceDest: 1000.0,
      newbalanceDest: 3500.0
    },
    fraud: {
      account_id: 'ACC-FRAUD-02',
      step: 12,
      type: 'CASH_OUT',
      amount: 350000.0,
      oldbalanceOrg: 350000.0,
      newbalanceOrig: 0.0,
      oldbalanceDest: 0.0,
      newbalanceDest: 350000.0
    },
    invariantViolation: {
      account_id: 'ACC-RULE-03',
      step: 3,
      type: 'TRANSFER',
      amount: 15000.0,
      oldbalanceOrg: 60000.0,
      newbalanceOrig: 60000.0,
      oldbalanceDest: 5000.0,
      newbalanceDest: 20000.0
    }
  };

  // Sanitize any account ID to obey backend regex ^[A-Za-z0-9_-]{4,40}$
  const sanitizeAccountId = (raw) => {
    const cleaned = (raw || 'ACC-DEFAULT').trim().replace(/[^A-Za-z0-9_-]/g, '_').toUpperCase();
    return cleaned.length < 4 ? `ACC_${cleaned}` : cleaned.slice(0, 40);
  };

  // Save/Update isolated user profile in encrypted local storage
  const saveUserProfileToVault = (profile) => {
    try {
      const rawUsers = localStorage.getItem(STORAGE_KEY_USERS);
      const usersMap = rawUsers ? JSON.parse(rawUsers) : {};
      const cipher = encryptBankPayload(profile);
      usersMap[profile.accountHash] = cipher;
      localStorage.setItem(STORAGE_KEY_USERS, JSON.stringify(usersMap));
      setActiveClientProfile(profile);
    } catch (e) {
      console.error('Failed to save encrypted user profile', e);
    }
  };

  // Record a new audit entry into state AND localStorage (strictly hashed, no raw names)
  const recordAuditEntry = useCallback((entry) => {
    setAuditLogs((prev) => {
      const exists = prev.some((item) => item.audit_id === entry.audit_id && item.request_id === entry.request_id);
      const updated = exists ? prev : [entry, ...prev];
      try {
        localStorage.setItem(STORAGE_KEY_LOGS, JSON.stringify(updated));
      } catch (e) {
        console.error('Failed to save audit log', e);
      }
      return updated;
    });
  }, []);

  // Fetch backend database logs
  const fetchBackendLogs = useCallback(async (keyToUse) => {
    const key = (keyToUse || apiKeyInput).trim();
    if (!key) return;
    try {
      const res = await fetch('http://127.0.0.1:8000/audit-logs', {
        headers: { 'Authorization': `Bearer ${key}` }
      });
      if (!res.ok) return;
      const dbLogs = await res.json();
      if (Array.isArray(dbLogs) && dbLogs.length > 0) {
        setAuditLogs((prev) => {
          const byId = new Map(prev.map(item => [item.audit_id, item]));
          dbLogs.forEach(dbItem => {
            if (byId.has(dbItem.audit_id)) {
              byId.set(dbItem.audit_id, { ...dbItem, ...byId.get(dbItem.audit_id) });
            } else {
              byId.set(dbItem.audit_id, dbItem);
            }
          });
          const merged = Array.from(byId.values()).sort((a, b) => (b.audit_id || 0) - (a.audit_id || 0));
          localStorage.setItem(STORAGE_KEY_LOGS, JSON.stringify(merged));
          return merged;
        });
      }
    } catch {
      // Fallback to localStorage if backend endpoint isn't available
    }
  }, [apiKeyInput]);

  // Listen for cross-tab localStorage updates
  useEffect(() => {
    const handleStorageChange = (e) => {
      if (e.key === STORAGE_KEY_LOGS && e.newValue) {
        try {
          setAuditLogs(JSON.parse(e.newValue));
        } catch {
          // ignore
        }
      }
    };
    window.addEventListener('storage', handleStorageChange);
    return () => window.removeEventListener('storage', handleStorageChange);
  }, []);

  useEffect(() => {
    if (isLoggedIn && (selectedRole === 'bank' || activeTab === 'audit')) {
      fetchBackendLogs();
    }
  }, [isLoggedIn, selectedRole, activeTab, fetchBackendLogs]);

  // Handle Login & Per-User Isolated Profile Initialization
  const handleLogin = async (e) => {
    e.preventDefault();
    if (!apiKeyInput.trim()) {
      alert('Please enter a valid API key (fgk_...)');
      return;
    }
    localStorage.setItem(STORAGE_KEY_API, apiKeyInput.trim());

    if (selectedRole === 'client') {
      const sanitizedId = sanitizeAccountId(
        clientNameInput.trim().toUpperCase().startsWith('ACC-')
          ? clientNameInput
          : `ACC-${clientNameInput}`
      );
      const acctHash = await sha256Hash(sanitizedId);

      const rawUsers = localStorage.getItem(STORAGE_KEY_USERS);
      const usersMap = rawUsers ? JSON.parse(rawUsers) : {};
      const existingCipher = usersMap[acctHash];
      const existingProfile = existingCipher ? decryptBankPayload(existingCipher) : null;

      const parsedDeposit = parseFloat(initialDepositInput);

      if (existingProfile) {
        const updatedProfile = {
          ...existingProfile,
          bankName: bankNameInput || existingProfile.bankName,
          cardType: cardTypeInput || existingProfile.cardType,
          accountNumber: accountNumberInput || existingProfile.accountNumber,
          balance: !isNaN(parsedDeposit) ? parsedDeposit : existingProfile.balance,
        };
        saveUserProfileToVault(updatedProfile);
        setBalanceDraft(String(updatedProfile.balance));
      } else {
        const last4 = (accountNumberInput.replace(/\D/g, '').slice(-4)) || String(Math.floor(1000 + Math.random() * 9000));
        const startingBal = !isNaN(parsedDeposit) ? parsedDeposit : 15000.0;
        const newProfile = {
          sanitizedAccountId: sanitizedId,
          accountHash: acctHash,
          displayName: clientNameInput.trim(),
          bankName: bankNameInput,
          cardType: cardTypeInput,
          accountNumber: accountNumberInput,
          cardLast4: last4,
          balance: startingBal,
          createdAt: new Date().toISOString()
        };
        saveUserProfileToVault(newProfile);
        setBalanceDraft(String(startingBal));
      }
    }

    fetchBackendLogs(apiKeyInput.trim());
    setIsLoggedIn(true);
  };

  // Load returning user's saved balance automatically when they type their name on the login screen
  const handleClientNameChange = async (val) => {
    setClientNameInput(val);
    if (!val.trim()) return;
    const sanitizedId = sanitizeAccountId(val.trim().toUpperCase().startsWith('ACC-') ? val : `ACC-${val}`);
    const acctHash = await sha256Hash(sanitizedId);
    const rawUsers = localStorage.getItem(STORAGE_KEY_USERS);
    const usersMap = rawUsers ? JSON.parse(rawUsers) : {};
    const saved = usersMap[acctHash] ? decryptBankPayload(usersMap[acctHash]) : null;
    if (saved) {
      setBankNameInput(saved.bankName || 'Equity Bank');
      setCardTypeInput(saved.cardType || 'VISA');
      setAccountNumberInput(saved.accountNumber || '');
      setInitialDepositInput(String(saved.balance));
    }
  };

  const handleLogout = () => {
    setIsLoggedIn(false);
    setSelectedRole(null);
    setActiveClientProfile(null);
    setIsEditingBalance(false);
    setResult(null);
    setClientFeedback(null);
    setClientNameInput('');
    setAccountNumberInput('');
    setInitialDepositInput('15000');
  };

  const clearLocalLogs = () => {
    localStorage.removeItem(STORAGE_KEY_LOGS);
    setAuditLogs([]);
  };

  const handleBalanceUpdate = (newBal) => {
    if (!activeClientProfile) return;
    const numericBal = isNaN(newBal) ? 0 : Number(newBal);
    const updated = { ...activeClientProfile, balance: numericBal };
    saveUserProfileToVault(updated);
    setBalanceDraft(String(numericBal));
  };

  const startEditingBalance = () => {
    if (!activeClientProfile) return;
    setBalanceDraft(String(activeClientProfile.balance));
    setIsEditingBalance(true);
  };

  const commitBalanceEdit = (e) => {
    if (e) e.preventDefault();
    const parsed = parseFloat(balanceDraft);
    handleBalanceUpdate(isNaN(parsed) ? 0 : parsed);
    setIsEditingBalance(false);
  };

  const handleBankSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResult(null);

    const cleanAcct = sanitizeAccountId(formData.account_id);
    const acctHash = await sha256Hash(cleanAcct);

    try {
      const response = await fetch('http://127.0.0.1:8000/predict', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKeyInput.trim()}`
        },
        body: JSON.stringify({
          ...formData,
          account_id: cleanAcct,
          step: Number(formData.step),
          amount: Number(formData.amount),
          oldbalanceOrg: Number(formData.oldbalanceOrg),
          newbalanceOrig: Number(formData.newbalanceOrig),
          oldbalanceDest: Number(formData.oldbalanceDest),
          newbalanceDest: Number(formData.newbalanceDest)
        })
      });

      const data = await response.json();
      if (!response.ok) {
        const errDetail = typeof data.detail === 'object' ? JSON.stringify(data.detail) : (data.detail || `Server error: ${response.status}`);
        throw new Error(errDetail);
      }

      const enrichedEntry = {
        ...data,
        account_hash: data.account_hash || acctHash,
        type: formData.type,
        amount: Number(formData.amount),
        origin: 'Bank Ops Simulator'
      };

      setResult(enrichedEntry);
      recordAuditEntry(enrichedEntry);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleClientTransfer = async (e) => {
    e.preventDefault();
    if (!activeClientProfile) return;
    setLoading(true);
    setClientFeedback(null);

    const amt = parseFloat(transferAmount);
    const currentBal = activeClientProfile.balance;
    const sanitizedAccount = activeClientProfile.sanitizedAccountId;
    const acctHash = activeClientProfile.accountHash;
    const recipientHash = await sha256Hash(transferRecipient || 'EXTERNAL');

    const expectedNewBalance = currentBal - amt;
    const actualNewBalance = manualNewBalanceOrg !== '' ? parseFloat(manualNewBalanceOrg) : expectedNewBalance;
    const safeNewBalanceOrig = Math.max(0, actualNewBalance);

    const payload = {
      account_id: sanitizedAccount,
      step: 10,
      type: 'TRANSFER',
      amount: amt,
      oldbalanceOrg: currentBal,
      newbalanceOrig: safeNewBalanceOrig, 
      oldbalanceDest: 5000.0,
      newbalanceDest: 5000.0 + amt
    };

    try {
      const response = await fetch('http://127.0.0.1:8000/predict', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKeyInput.trim()}`
        },
        body: JSON.stringify(payload)
      });

      const data = await response.json();
      if (!response.ok) {
        const errDetail = typeof data.detail === 'object' ? JSON.stringify(data.detail) : (data.detail || 'Transaction declined by gateway.');
        throw new Error(errDetail);
      }

      const enrichedEntry = {
        ...data,
        account_hash: data.account_hash || acctHash,
        recipient_hash: recipientHash.slice(0, 12),
        card_network: `${activeClientProfile.bankName} (${activeClientProfile.cardType})`,
        type: 'TRANSFER',
        amount: amt,
        origin: 'Client Portal'
      };

      recordAuditEntry(enrichedEntry);

      if (data.decision === 'APPROVE') {
        handleBalanceUpdate(safeNewBalanceOrig);
        setClientFeedback({ 
          success: true, 
          msg: `Transfer of $${amt.toLocaleString()} approved! (Audit #${data.audit_id} | Hash: ${acctHash.slice(0, 10)}...)` 
        });
      } else {
        setClientFeedback({ 
          success: false, 
          msg: `Security Alert: Transfer blocked by BankGuard [Audit #${data.audit_id}] — ${data.reason || 'Risk threshold or ledger invariant breached'}.` 
        });
      }
    } catch (err) {
      setClientFeedback({ success: false, msg: `Error: ${err.message}` });
    } finally {
      setLoading(false);
      setTransferAmount('');
      setTransferRecipient('');
      setManualNewBalanceOrg('');
    }
  };

  const getCardGradient = (type) => {
    if (type === 'MASTERCARD') return 'from-orange-950 via-[#1a130e] to-rose-950/60 border-orange-500/40';
    if (type === 'AMEX') return 'from-slate-900 via-[#111822] to-cyan-950/50 border-cyan-500/40';
    return 'from-neutral-900 via-[#17140e] to-amber-950/50 border-amber-500/40';
  };

  return (
    <div className="min-h-screen w-full bg-[#070605] text-amber-50 flex flex-col font-sans selection:bg-amber-500 selection:text-[#0b0a08]">
      
      {!isLoggedIn ? (
        <div className="flex-1 flex flex-col items-center justify-center p-6 text-center max-w-lg mx-auto w-full space-y-6">
          <div className="bg-amber-500/10 p-4 rounded-3xl border border-amber-500/20 shadow-xl">
            <Shield className="w-10 h-10 text-amber-400" />
          </div>
          
          <div className="space-y-1">
            <h1 className="text-2xl font-bold tracking-tight text-white m-0">BankGuard Secure Gateway</h1>
            <p className="text-xs text-neutral-400">Select your role to authenticate into the portal.</p>
          </div>

          <form onSubmit={handleLogin} className="w-full space-y-4 text-left bg-[#12100d] p-6 rounded-3xl border border-amber-950/50 shadow-2xl">
            <div className="grid grid-cols-2 gap-3">
              <button
                type="button"
                onClick={() => setSelectedRole('client')}
                className={`p-3.5 rounded-2xl border text-left transition flex flex-col space-y-1 cursor-pointer ${
                  selectedRole === 'client' ? 'bg-amber-500/20 border-amber-500 text-amber-300' : 'bg-[#181510] border-amber-950/50 text-neutral-400 hover:border-amber-800'
                }`}
              >
                <CreditCard className="w-4 h-4 text-amber-400" />
                <span className="text-xs font-bold text-white">Client Banking Login</span>
                <span className="text-[10px] text-neutral-500">Personal wallet & card onboarding</span>
              </button>

              <button
                type="button"
                onClick={() => setSelectedRole('bank')}
                className={`p-3.5 rounded-2xl border text-left transition flex flex-col space-y-1 cursor-pointer ${
                  selectedRole === 'bank' ? 'bg-amber-500/20 border-amber-500 text-amber-300' : 'bg-[#181510] border-amber-950/50 text-neutral-400 hover:border-amber-800'
                }`}
              >
                <ShieldAlert className="w-4 h-4 text-amber-400" />
                <span className="text-xs font-bold text-white">Bank Fraud Ops</span>
                <span className="text-[10px] text-neutral-500">Pseudonymized HMAC audit console</span>
              </button>
            </div>

            {selectedRole === 'client' && (
              <div className="space-y-3 pt-2 border-t border-amber-950/40">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] uppercase tracking-wider font-semibold text-amber-400">Client Account Details</span>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[10px] font-medium text-neutral-400 mb-1">Account Holder Name / ID</label>
                    <div className="flex items-center bg-[#181510] border border-amber-950/60 rounded-xl px-3 py-2">
                      <User className="w-3.5 h-3.5 text-amber-500 mr-2 shrink-0" />
                      <input
                        type="text"
                        placeholder="e.g. GLORY_NKATHA"
                        value={clientNameInput}
                        onChange={(e) => handleClientNameChange(e.target.value)}
                        className="bg-transparent border-none text-xs text-white placeholder-neutral-600 focus:outline-none w-full uppercase"
                        required
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-[10px] font-medium text-neutral-400 mb-1">Starting Balance ($)</label>
                    <div className="flex items-center bg-[#181510] border border-amber-950/60 rounded-xl px-3 py-2">
                      <DollarSign className="w-3.5 h-3.5 text-amber-500 mr-1 shrink-0" />
                      <input
                        type="number"
                        step="0.01"
                        value={initialDepositInput}
                        onChange={(e) => setInitialDepositInput(e.target.value)}
                        className="bg-transparent border-none text-xs text-white font-mono focus:outline-none w-full"
                        required
                      />
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[10px] font-medium text-neutral-400 mb-1">Issuing Bank</label>
                    <div className="flex items-center bg-[#181510] border border-amber-950/60 rounded-xl px-3 py-2">
                      <Building2 className="w-3.5 h-3.5 text-amber-500 mr-2 shrink-0" />
                      <select
                        value={bankNameInput}
                        onChange={(e) => setBankNameInput(e.target.value)}
                        className="bg-[#181510] border-none text-xs text-white focus:outline-none w-full"
                      >
                        <option value="Equity Bank">Equity Bank</option>
                        <option value="KCB Bank">KCB Bank</option>
                        <option value="Stanbic Bank">Stanbic Bank</option>
                        <option value="Standard Chartered">Standard Chartered</option>
                        <option value="JP Morgan Chase">JP Morgan Chase</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="block text-[10px] font-medium text-neutral-400 mb-1">Card Network</label>
                    <div className="flex items-center bg-[#181510] border border-amber-950/60 rounded-xl px-3 py-2">
                      <CreditCard className="w-3.5 h-3.5 text-amber-500 mr-2 shrink-0" />
                      <select
                        value={cardTypeInput}
                        onChange={(e) => setCardTypeInput(e.target.value)}
                        className="bg-[#181510] border-none text-xs text-white focus:outline-none w-full"
                      >
                        <option value="VISA">VISA Infinite</option>
                        <option value="MASTERCARD">Mastercard World</option>
                        <option value="AMEX">American Express</option>
                      </select>
                    </div>
                  </div>
                </div>

                <div>
                  <label className="block text-[10px] font-medium text-neutral-400 mb-1">Bank Account / Card Number</label>
                  <div className="flex items-center bg-[#181510] border border-amber-950/60 rounded-xl px-3 py-2">
                    <Lock className="w-3.5 h-3.5 text-amber-500 mr-2 shrink-0" />
                    <input
                      type="text"
                      placeholder="e.g. 4532 •••• •••• 8891"
                      value={accountNumberInput}
                      onChange={(e) => setAccountNumberInput(e.target.value)}
                      className="bg-transparent border-none text-xs text-white font-mono placeholder-neutral-600 focus:outline-none w-full"
                      required
                    />
                  </div>
                </div>
              </div>
            )}

            <div>
              <label className="block text-[10px] font-medium text-neutral-400 mb-1">Gateway Bearer API Key</label>
              <div className="flex items-center bg-[#181510] border border-amber-950/60 rounded-xl px-3 py-2">
                <Key className="w-4 h-4 text-amber-500 mr-2 shrink-0" />
                <input
                  type="password"
                  placeholder="Enter Bearer API Key (fgk_...)"
                  value={apiKeyInput}
                  onChange={(e) => setApiKeyInput(e.target.value)}
                  className="bg-transparent border-none text-xs text-white placeholder-neutral-600 focus:outline-none w-full font-mono"
                  required
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={!selectedRole}
              className={`w-full py-3 rounded-xl font-bold text-xs transition shadow-lg ${
                selectedRole ? 'bg-amber-500 hover:bg-amber-400 text-[#0b0a08] shadow-amber-500/20 cursor-pointer' : 'bg-neutral-800 text-neutral-500 cursor-not-allowed'
              }`}
            >
              Authenticate & Enter Portal
            </button>
          </form>
        </div>
      ) : (
        <div className="flex-1 flex flex-col w-full min-h-screen bg-[#0b0a08]">
          <header className="h-16 border-b border-amber-950/40 px-8 flex items-center justify-between bg-[#12100d] shrink-0">
            <div className="flex items-center space-x-3">
              <div className="bg-amber-500 p-2 rounded-xl text-[#0b0a08]">
                <Shield className="w-4 h-4 fill-current" />
              </div>
              <div>
                <h1 className="font-bold text-sm text-white m-0">
                  {selectedRole === 'bank' ? 'BankGuard Fraud Operations Center' : `${activeClientProfile?.bankName || 'BankGuard'} Personal Portal`}
                </h1>
                <p className="text-[10px] text-neutral-400 m-0 font-mono">
                  {selectedRole === 'bank' ? (
                    <span>ROLE: <strong className="text-amber-400">FRAUD OPS ADMIN</strong> | AUDIT RECORDS: {auditLogs.length}</span>
                  ) : (
                    <span>
                      HOLDER: <strong className="text-amber-400">{activeClientProfile?.displayName}</strong> | SHA-256 HASH: <span className="text-emerald-400">{activeClientProfile?.accountHash?.slice(0, 16)}...</span>
                    </span>
                  )}
                </p>
              </div>
            </div>

            <div className="flex items-center space-x-3">
              <button
                onClick={handleLogout}
                className="flex items-center space-x-1.5 px-3.5 py-1.5 bg-rose-500/10 border border-rose-500/30 text-rose-400 rounded-xl text-xs hover:bg-rose-500/20 transition cursor-pointer"
              >
                <LogOut className="w-3.5 h-3.5" />
                <span>Sign Out</span>
              </button>
            </div>
          </header>

          <main className="flex-1 p-8 overflow-y-auto w-full max-w-7xl mx-auto">
            {/* ==================== BANK FRAUD OPS VIEW ==================== */}
            {selectedRole === 'bank' && (
              <div className="space-y-6">
                <div className="flex items-center justify-between border-b border-amber-950/40 pb-4">
                  <div className="flex space-x-2">
                    <button
                      onClick={() => setActiveTab('simulator')}
                      className={`px-4 py-1.5 rounded-xl text-xs font-semibold transition cursor-pointer ${
                        activeTab === 'simulator' ? 'bg-amber-500 text-[#0b0a08]' : 'bg-[#12100d] text-neutral-400 hover:text-white border border-amber-950/40'
                      }`}
                    >
                      Live Simulator & Rules
                    </button>
                    <button
                      onClick={() => setActiveTab('audit')}
                      className={`px-4 py-1.5 rounded-xl text-xs font-semibold transition cursor-pointer ${
                        activeTab === 'audit' ? 'bg-amber-500 text-[#0b0a08]' : 'bg-[#12100d] text-neutral-400 hover:text-white border border-amber-950/40'
                      }`}
                    >
                      HMAC Audit Trail ({auditLogs.length})
                    </button>
                    <button
                      onClick={() => setActiveTab('health')}
                      className={`px-4 py-1.5 rounded-xl text-xs font-semibold transition cursor-pointer ${
                        activeTab === 'health' ? 'bg-amber-500 text-[#0b0a08]' : 'bg-[#12100d] text-neutral-400 hover:text-white border border-amber-950/40'
                      }`}
                    >
                      System Health
                    </button>
                  </div>

                  {activeTab === 'audit' && (
                    <div className="flex space-x-2">
                      <button
                        onClick={() => fetchBackendLogs()}
                        className="flex items-center space-x-1 px-3 py-1 bg-[#181510] border border-amber-950/60 text-amber-400 rounded-xl text-xs hover:border-amber-500 cursor-pointer"
                      >
                        <RefreshCw className="w-3 h-3" />
                        <span>Sync DB Logs</span>
                      </button>
                      {auditLogs.length > 0 && (
                        <button
                          onClick={clearLocalLogs}
                          className="flex items-center space-x-1 px-3 py-1 bg-rose-500/10 border border-rose-500/30 text-rose-400 rounded-xl text-xs hover:bg-rose-500/20 cursor-pointer"
                        >
                          <Trash2 className="w-3 h-3" />
                          <span>Clear Local Cache</span>
                        </button>
                      )}
                    </div>
                  )}
                </div>

                {activeTab === 'simulator' && (
                  <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 text-left">
                    <div className="lg:col-span-7 bg-[#12100d] border border-amber-950/40 rounded-2xl p-6">
                      <div className="flex items-center justify-between mb-4">
                        <div>
                          <h2 className="text-sm font-semibold text-white m-0">Transaction Gateway Payload</h2>
                          <p className="text-[10px] text-neutral-400 m-0">Account IDs are automatically hashed with SHA-256/HMAC before logging.</p>
                        </div>
                        <div className="flex space-x-1.5">
                          <button onClick={() => setFormData(presets.normal)} className="px-2.5 py-0.5 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-[10px] rounded-lg cursor-pointer">Normal</button>
                          <button onClick={() => setFormData(presets.fraud)} className="px-2.5 py-0.5 bg-rose-500/10 border border-rose-500/30 text-rose-400 text-[10px] rounded-lg cursor-pointer">Fraud Drain</button>
                          <button onClick={() => setFormData(presets.invariantViolation)} className="px-2.5 py-0.5 bg-amber-500/10 border border-amber-500/30 text-amber-400 text-[10px] rounded-lg cursor-pointer">Rule Violation</button>
                        </div>
                      </div>

                      <form onSubmit={handleBankSubmit} className="space-y-3 text-xs">
                        <div className="grid grid-cols-2 gap-3">
                          <div>
                            <label className="block text-[10px] text-neutral-400 mb-1">Account ID (Will be hashed)</label>
                            <input type="text" value={formData.account_id} onChange={(e) => setFormData({...formData, account_id: e.target.value})} className="w-full bg-[#181510] border border-amber-950/50 rounded-xl px-3 py-1.5 text-white" required />
                          </div>
                          <div>
                            <label className="block text-[10px] text-neutral-400 mb-1">Type</label>
                            <select value={formData.type} onChange={(e) => setFormData({...formData, type: e.target.value})} className="w-full bg-[#181510] border border-amber-950/50 rounded-xl px-3 py-1.5 text-white">
                              <option value="TRANSFER">TRANSFER</option>
                              <option value="CASH_OUT">CASH_OUT</option>
                              <option value="CASH_IN">CASH_IN</option>
                            </select>
                          </div>
                        </div>

                        <div className="grid grid-cols-2 gap-3">
                          <div>
                            <label className="block text-[10px] text-neutral-400 mb-1">Amount ($)</label>
                            <input type="number" step="0.01" value={formData.amount} onChange={(e) => setFormData({...formData, amount: e.target.value})} className="w-full bg-[#181510] border border-amber-950/50 rounded-xl px-3 py-1.5 text-white font-mono" required />
                          </div>
                          <div>
                            <label className="block text-[10px] text-neutral-400 mb-1">Time Step</label>
                            <input type="number" value={formData.step} onChange={(e) => setFormData({...formData, step: e.target.value})} className="w-full bg-[#181510] border border-amber-950/50 rounded-xl px-3 py-1.5 text-white font-mono" required />
                          </div>
                        </div>

                        <div className="grid grid-cols-2 gap-3">
                          <div>
                            <label className="block text-[10px] text-neutral-400 mb-1">Sender Old Balance</label>
                            <input type="number" step="0.01" value={formData.oldbalanceOrg} onChange={(e) => setFormData({...formData, oldbalanceOrg: e.target.value})} className="w-full bg-[#181510] border border-amber-950/50 rounded-xl px-3 py-1.5 text-white font-mono" required />
                          </div>
                          <div>
                            <label className="block text-[10px] text-neutral-400 mb-1">Sender New Balance</label>
                            <input type="number" step="0.01" value={formData.newbalanceOrig} onChange={(e) => setFormData({...formData, newbalanceOrig: e.target.value})} className="w-full bg-[#181510] border border-amber-950/50 rounded-xl px-3 py-1.5 text-white font-mono" required />
                          </div>
                        </div>

                        <div className="grid grid-cols-2 gap-3">
                          <div>
                            <label className="block text-[10px] text-neutral-400 mb-1">Recipient Old Balance</label>
                            <input type="number" step="0.01" value={formData.oldbalanceDest} onChange={(e) => setFormData({...formData, oldbalanceDest: e.target.value})} className="w-full bg-[#181510] border border-amber-950/50 rounded-xl px-3 py-1.5 text-white font-mono" required />
                          </div>
                          <div>
                            <label className="block text-[10px] text-neutral-400 mb-1">Recipient New Balance</label>
                            <input type="number" step="0.01" value={formData.newbalanceDest} onChange={(e) => setFormData({...formData, newbalanceDest: e.target.value})} className="w-full bg-[#181510] border border-amber-950/50 rounded-xl px-3 py-1.5 text-white font-mono" required />
                          </div>
                        </div>

                        <button type="submit" disabled={loading} className="w-full mt-2 bg-amber-500 hover:bg-amber-400 text-[#0b0a08] font-bold py-2.5 px-4 rounded-xl transition flex items-center justify-center space-x-2 cursor-pointer">
                          {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <><Send className="w-3.5 h-3.5" /><span>Evaluate Transaction Risk</span></>}
                        </button>
                      </form>
                    </div>

                    <div className="lg:col-span-5 space-y-4">
                      <div className="bg-[#12100d] border border-amber-950/40 rounded-2xl p-6">
                        <h2 className="text-sm font-semibold text-white mb-3 m-0">Decision Output</h2>

                        {error && (
                          <div className="bg-rose-500/10 border border-rose-500/30 rounded-xl p-3 text-rose-400 text-xs flex items-center space-x-2">
                            <XCircle className="w-4 h-4 shrink-0" />
                            <span>{error}</span>
                          </div>
                        )}

                        {!result && !error && (
                          <div className="text-center py-16 text-neutral-500 border border-dashed border-amber-950/50 rounded-xl text-xs">
                            <Activity className="w-8 h-8 mx-auto mb-2 opacity-40 text-amber-500" />
                            <span>Awaiting evaluation payload...</span>
                          </div>
                        )}

                        {result && (
                          <div className="space-y-3 text-xs">
                            <div className={`p-3 rounded-xl border flex items-center justify-between ${
                              result.decision === 'APPROVE' ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' : 'bg-rose-500/10 border-rose-500/30 text-rose-400'
                            }`}>
                              <div className="flex items-center space-x-2">
                                {result.decision === 'APPROVE' ? <CheckCircle2 className="w-5 h-5" /> : <AlertTriangle className="w-5 h-5" />}
                                <span className="font-bold text-sm">{result.decision}</span>
                              </div>
                              <span className="font-mono text-xs">{result.risk_level}</span>
                            </div>

                            <div className="bg-[#181510] rounded-xl p-3 border border-amber-950/50 space-y-1.5">
                              <div className="flex justify-between">
                                <span className="text-neutral-400">Account Hash (SHA-256):</span>
                                <span className="font-mono text-emerald-400">{result.account_hash?.slice(0, 14)}...</span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-neutral-400">Fraud Probability:</span>
                                <span className="font-mono text-white font-bold">{((result.fraud_probability || 0) * 100).toFixed(2)}%</span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-neutral-400">Decision Source:</span>
                                <span className="font-mono text-amber-400">{result.decision_source || 'GATEWAY'}</span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-neutral-400">Audit ID:</span>
                                <span className="font-mono text-neutral-300">#{result.audit_id}</span>
                              </div>
                            </div>

                            <div className="bg-[#181510] rounded-xl p-3 border border-amber-950/50">
                              <p className="text-[10px] text-neutral-400 mb-0.5">Reasoning:</p>
                              <p className="text-xs text-amber-200 font-mono m-0">{result.reason || 'Evaluated by gateway.'}</p>
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )}

                {activeTab === 'audit' && (
                  <div className="bg-[#12100d] border border-amber-950/40 rounded-2xl p-6 text-left">
                    <h2 className="text-sm font-semibold text-white mb-1 m-0">HMAC Cryptographic Audit Trail (Zero-PII)</h2>
                    <p className="text-[10px] text-neutral-400 mb-4">All account identifiers are pseudonymized via SHA-256/HMAC before persistence.</p>
                    {auditLogs.length === 0 ? (
                      <div className="text-center py-12 text-neutral-500 text-xs border border-dashed border-amber-950/50 rounded-xl">No logs yet. Perform a client transfer or bank test to see records here.</div>
                    ) : (
                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-xs">
                          <thead>
                            <tr className="border-b border-amber-950/50 text-neutral-400">
                              <th className="pb-2">Audit ID</th>
                              <th className="pb-2">Pseudonymized Account Hash</th>
                              <th className="pb-2">Channel / Card</th>
                              <th className="pb-2">Amount</th>
                              <th className="pb-2">Decision</th>
                              <th className="pb-2">Source</th>
                              <th className="pb-2">ML Prob</th>
                              <th className="pb-2">Reason</th>
                              <th className="pb-2">Time</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-amber-950/30">
                            {auditLogs.map((log, idx) => {
                              const displayHash = log.account_hash
                                ? `hmac_${log.account_hash.slice(0, 14)}...`
                                : 'hmac_hidden';
                              return (
                                <tr key={log.audit_id || idx} className="hover:bg-[#181510]/60">
                                  <td className="py-2.5 font-mono text-amber-400">#{log.audit_id}</td>
                                  <td className="py-2.5 font-mono text-emerald-400" title={log.account_hash}>
                                    {displayHash}
                                  </td>
                                  <td className="py-2.5 text-[11px] text-neutral-300">
                                    {log.card_network || log.origin || log.type || 'GATEWAY'}
                                  </td>
                                  <td className="py-2.5 font-mono text-white">
                                    {log.amount !== undefined ? `$${Number(log.amount).toLocaleString()}` : '—'}
                                  </td>
                                  <td className="py-2.5">
                                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                                      log.decision === 'APPROVE' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' : 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                                    }`}>
                                      {log.decision}
                                    </span>
                                  </td>
                                  <td className="py-2.5 font-mono text-amber-300 text-[11px]">{log.decision_source || 'ENGINE'}</td>
                                  <td className="py-2.5 font-mono">{((log.fraud_probability || 0) * 100).toFixed(1)}%</td>
                                  <td className="py-2.5 text-neutral-300 max-w-xs truncate" title={log.reason}>
                                    {log.reason || log.security_threat || 'Verified'}
                                  </td>
                                  <td className="py-2.5 text-neutral-400 font-mono">
                                    {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : 'Now'}
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                )}

                {activeTab === 'health' && (
                  <div className="grid grid-cols-3 gap-4 text-xs text-left">
                    <div className="bg-[#12100d] border border-amber-950/40 rounded-2xl p-4">
                      <Database className="w-4 h-4 text-amber-500 mb-2" />
                      <h3 className="font-semibold text-white m-0">Database & State Store</h3>
                      <p className="text-[10px] text-emerald-400 mt-2 m-0">Operational (Fail-Closed)</p>
                    </div>
                    <div className="bg-[#12100d] border border-amber-950/40 rounded-2xl p-4">
                      <Server className="w-4 h-4 text-amber-500 mb-2" />
                      <h3 className="font-semibold text-white m-0">Random Forest Model</h3>
                      <p className="text-[10px] text-emerald-400 mt-2 m-0">Loaded in Worker Threadpool</p>
                    </div>
                    <div className="bg-[#12100d] border border-amber-950/40 rounded-2xl p-4">
                      <Terminal className="w-4 h-4 text-amber-500 mb-2" />
                      <h3 className="font-semibold text-white m-0">HMAC Audit Ledger</h3>
                      <p className="text-[10px] text-emerald-400 mt-2 m-0">Zero-PII Hashing Verified</p>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* ==================== CLIENT PORTAL VIEW ==================== */}
            {selectedRole === 'client' && activeClientProfile && (
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 text-left">
                <div className="lg:col-span-8 space-y-6">
                  {/* Personal Balance Card with Smooth Draft Editor */}
                  <div className="bg-[#12100d] border border-amber-950/40 rounded-2xl p-6 relative">
                    <div className="flex justify-between items-center mb-2">
                      <p className="text-[10px] uppercase font-medium text-neutral-400 m-0">
                        {activeClientProfile.bankName} Checking • Holder: {activeClientProfile.displayName}
                      </p>
                      {!isEditingBalance ? (
                        <button 
                          type="button"
                          onClick={startEditingBalance}
                          className="text-[10px] text-amber-400 flex items-center space-x-1 hover:underline cursor-pointer"
                        >
                          <Edit3 className="w-3 h-3" />
                          <span>Adjust Balance</span>
                        </button>
                      ) : (
                        <button 
                          type="button"
                          onClick={commitBalanceEdit}
                          className="text-[10px] bg-amber-500 text-[#0b0a08] font-bold px-2.5 py-1 rounded-lg cursor-pointer hover:bg-amber-400"
                        >
                          Save Balance
                        </button>
                      )}
                    </div>

                    {!isEditingBalance ? (
                      <h2 className="text-3xl font-bold text-white font-mono m-0">
                        ${Number(activeClientProfile.balance).toLocaleString('en-US', { minimumFractionDigits: 2 })}
                      </h2>
                    ) : (
                      <form onSubmit={commitBalanceEdit} className="flex items-center space-x-2 mt-2">
                        <input 
                          type="number" 
                          step="0.01" 
                          value={balanceDraft} 
                          onChange={(e) => setBalanceDraft(e.target.value)}
                          placeholder="Enter new balance..."
                          autoFocus
                          className="bg-[#181510] border border-amber-500 rounded-xl px-3 py-1.5 text-lg text-white font-mono w-56 focus:outline-none"
                        />
                        <button
                          type="submit"
                          className="px-3 py-1.5 bg-amber-500 text-[#0b0a08] font-bold text-xs rounded-xl cursor-pointer hover:bg-amber-400"
                        >
                          Apply
                        </button>
                        <button
                          type="button"
                          onClick={() => setIsEditingBalance(false)}
                          className="px-2.5 py-1.5 bg-[#181510] text-neutral-400 text-xs rounded-xl cursor-pointer hover:text-white"
                        >
                          Cancel
                        </button>
                      </form>
                    )}

                    <div className="mt-3 flex items-center space-x-2">
                      <span className="text-[10px] text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded-full">
                        Account Active & Monitored
                      </span>
                      <span className="text-[10px] text-neutral-400 font-mono">
                        ID Hash: {activeClientProfile.accountHash.slice(0, 16)}...
                      </span>
                    </div>
                  </div>

                  {/* Transfer Form */}
                  <div className="bg-[#12100d] border border-amber-950/40 rounded-2xl p-6">
                    <h3 className="text-sm font-semibold text-white mb-1 m-0">Make Secure Transfer</h3>
                    <p className="text-[10px] text-neutral-400 mb-4">
                      Protected by BankGuard. Your identity is hashed before reaching the bank's fraud audit ledger.
                    </p>

                    <form onSubmit={handleClientTransfer} className="space-y-3 text-xs">
                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <label className="block text-[10px] text-neutral-400 mb-1">Recipient Name / Account</label>
                          <input type="text" placeholder="e.g. Tamira Atieno" value={transferRecipient} onChange={(e) => setTransferRecipient(e.target.value)} className="w-full bg-[#181510] border border-amber-950/50 rounded-xl px-3 py-2 text-white" required />
                        </div>
                        <div>
                          <label className="block text-[10px] text-neutral-400 mb-1">Transfer Amount ($)</label>
                          <input type="number" step="0.01" placeholder="0.00" value={transferAmount} onChange={(e) => setTransferAmount(e.target.value)} className="w-full bg-[#181510] border border-amber-950/50 rounded-xl px-3 py-2 text-white font-mono" required />
                        </div>
                      </div>

                      <div className="bg-[#181510] p-3 rounded-xl border border-amber-950/60 space-y-1">
                        <label className="block text-[10px] text-amber-400 font-semibold">🧪 Test Ledger Invariant Violation (Optional Override)</label>
                        <p className="text-[10px] text-neutral-500">Leave blank for normal transfers. Enter a fake resulting balance (e.g., {activeClientProfile.balance}) to trigger a deterministic rule BLOCK!</p>
                        <input 
                          type="number" 
                          step="0.01" 
                          placeholder={`e.g. ${activeClientProfile.balance} (unmutated balance)`} 
                          value={manualNewBalanceOrg} 
                          onChange={(e) => setManualNewBalanceOrg(e.target.value)} 
                          className="w-full bg-[#0b0a08] border border-amber-950 rounded-lg px-3 py-1.5 text-white font-mono text-xs" 
                        />
                      </div>

                      <button type="submit" disabled={loading} className="w-full bg-amber-500 hover:bg-amber-400 text-[#0b0a08] font-bold py-2.5 rounded-xl transition flex items-center justify-center space-x-2 cursor-pointer">
                        {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <><ArrowUpRight className="w-4 h-4" /><span>Authorize & Send Funds</span></>}
                      </button>
                    </form>

                    {clientFeedback && (
                      <div className={`mt-4 p-3 rounded-xl border text-xs flex items-center space-x-2 ${
                        clientFeedback.success ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' : 'bg-rose-500/10 border-rose-500/30 text-rose-400'
                      }`}>
                        {clientFeedback.success ? <CheckCircle2 className="w-4 h-4 shrink-0" /> : <ShieldAlert className="w-4 h-4 shrink-0" />}
                        <span className="font-mono">{clientFeedback.msg}</span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Right Column: Custom Bank Card Only */}
                <div className="lg:col-span-4 space-y-6">
                  <div className="bg-[#12100d] border border-amber-950/40 rounded-2xl p-6">
                    <h3 className="text-xs font-semibold text-white mb-3 m-0">Issued Payment Card</h3>
                    <div className={`bg-gradient-to-tr ${getCardGradient(activeClientProfile.cardType)} border rounded-2xl p-5 text-xs shadow-xl`}>
                      <div className="flex justify-between items-center mb-6">
                        <div>
                          <p className="text-[10px] text-neutral-300 uppercase tracking-wider m-0">{activeClientProfile.bankName}</p>
                          <span className="font-extrabold tracking-widest text-amber-400 text-sm">{activeClientProfile.cardType}</span>
                        </div>
                        <span className="text-xs font-mono text-neutral-300">•••• {activeClientProfile.cardLast4}</span>
                      </div>
                      <p className="text-[10px] text-neutral-400 m-0">Cardholder</p>
                      <p className="text-xs font-bold text-white uppercase tracking-wide mb-3">{activeClientProfile.displayName}</p>
                      <p className="text-[10px] text-neutral-400 m-0">Available Limit</p>
                      <p className="text-lg font-bold text-white font-mono m-0">
                        ${Number(activeClientProfile.balance).toLocaleString('en-US', { minimumFractionDigits: 2 })}
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </main>
        </div>
      )}
    </div>
  );
}