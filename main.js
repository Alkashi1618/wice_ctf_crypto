const { useState, useEffect, useRef } = React;

// ============ UTILITAIRES ============
const downloadFile = (content, filename, mimeType = 'text/plain') => {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
};

const readFile = (file) => {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = (e) => resolve(e.target.result);
        reader.onerror = reject;
        reader.readAsText(file);
    });
};

// ============ ICÔNES SVG ============
const Icons = {
    Sun: ({ className = "w-6 h-6" }) => (
        <svg className={className} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
            <circle cx="12" cy="12" r="5"/>
            <line x1="12" y1="1" x2="12" y2="3"/>
            <line x1="12" y1="21" x2="12" y2="23"/>
            <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/>
            <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
            <line x1="1" y1="12" x2="3" y2="12"/>
            <line x1="21" y1="12" x2="23" y2="12"/>
            <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/>
            <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
        </svg>
    ),
    Moon: ({ className = "w-6 h-6" }) => (
        <svg className={className} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
        </svg>
    ),
    Lock: ({ className = "w-6 h-6" }) => (
        <svg className={className} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
    ),
    Unlock: ({ className = "w-6 h-6" }) => (
        <svg className={className} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0 1 9.9-1"/>
        </svg>
    ),
    Key: ({ className = "w-6 h-6" }) => (
        <svg className={className} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
            <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
        </svg>
    ),
    Shield: ({ className = "w-6 h-6" }) => (
        <svg className={className} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
    ),
    Download: ({ className = "w-6 h-6" }) => (
        <svg className={className} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
            <polyline points="7 10 12 15 17 10"/>
            <line x1="12" y1="15" x2="12" y2="3"/>
        </svg>
    ),
    Upload: ({ className = "w-6 h-6" }) => (
        <svg className={className} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
            <polyline points="17 8 12 3 7 8"/>
            <line x1="12" y1="3" x2="12" y2="15"/>
        </svg>
    ),
    Copy: ({ className = "w-6 h-6" }) => (
        <svg className={className} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
        </svg>
    ),
    Check: ({ className = "w-6 h-6" }) => (
        <svg className={className} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
            <polyline points="20 6 9 17 4 12"/>
        </svg>
    ),
    X: ({ className = "w-6 h-6" }) => (
        <svg className={className} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
            <line x1="18" y1="6" x2="6" y2="18"/>
            <line x1="6" y1="6" x2="18" y2="18"/>
        </svg>
    ),
    Hash: ({ className = "w-6 h-6" }) => (
        <svg className={className} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
            <line x1="4" y1="9" x2="20" y2="9"/>
            <line x1="4" y1="15" x2="20" y2="15"/>
            <line x1="10" y1="3" x2="8" y2="21"/>
            <line x1="16" y1="3" x2="14" y2="21"/>
        </svg>
    ),
    Cpu: ({ className = "w-6 h-6" }) => (
        <svg className={className} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
            <rect x="4" y="4" width="16" height="16" rx="2"/>
            <rect x="9" y="9" width="6" height="6"/>
            <path d="M9 2v2M15 2v2M9 22v2M15 22v2M2 9h2M2 15h2M22 9h2M22 15h2"/>
        </svg>
    ),
    FileKey: ({ className = "w-6 h-6" }) => (
        <svg className={className} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
            <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/>
            <circle cx="10" cy="16" r="2"/>
            <path d="m16 10-4.5 4.5M15 11l1 1"/>
        </svg>
    ),
    Alert: ({ className = "w-6 h-6" }) => (
        <svg className={className} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
            <circle cx="12" cy="12" r="10"/>
            <line x1="12" y1="8" x2="12" y2="12"/>
            <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
    ),
    Trash: ({ className = "w-6 h-6" }) => (
        <svg className={className} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
            <polyline points="3 6 5 6 21 6"/>
            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
        </svg>
    ),
};

// ============ COMPOSANTS RÉUTILISABLES ============
const Button = ({ variant = 'primary', children, onClick, disabled, className = '', icon: Icon, fullWidth = false }) => {
    const variants = {
        primary: 'bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 text-white shadow-lg',
        secondary: 'bg-gray-700 hover:bg-gray-600 text-white',
        outline: 'border-2 border-indigo-500 text-indigo-400 hover:bg-indigo-500/10',
        success: 'bg-green-600 hover:bg-green-700 text-white',
        danger: 'bg-red-600 hover:bg-red-700 text-white',
    };

    return (
        <button
            onClick={onClick}
            disabled={disabled}
            className={`flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg font-medium transition-all disabled:opacity-50 disabled:cursor-not-allowed ${variants[variant]} ${fullWidth ? 'w-full' : ''} ${className}`}
        >
            {Icon && <Icon className="w-5 h-5" />}
            {children}
        </button>
    );
};

const Alert = ({ type = 'info', children, onClose }) => {
    const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
    const styles = {
        success: isDark ? 'bg-green-500/20 border-green-500 text-green-300' : 'bg-green-100 border-green-500 text-green-700',
        error: isDark ? 'bg-red-500/20 border-red-500 text-red-300' : 'bg-red-100 border-red-500 text-red-700',
        warning: isDark ? 'bg-yellow-500/20 border-yellow-500 text-yellow-300' : 'bg-yellow-100 border-yellow-500 text-yellow-700',
        info: isDark ? 'bg-blue-500/20 border-blue-500 text-blue-300' : 'bg-blue-100 border-blue-500 text-blue-700'
    };

    return (
        <div className={`flex items-start gap-3 p-4 rounded-lg border ${styles[type]} mb-4 fade-in`}>
            <Icons.Alert className="w-5 h-5 flex-shrink-0 mt-0.5" />
            <div className="flex-1 text-sm">{children}</div>
            {onClose && (
                <button onClick={onClose} className="flex-shrink-0 hover:opacity-70 transition-opacity">
                    <Icons.X className="w-4 h-4" />
                </button>
            )}
        </div>
    );
};

// ============ GESTIONNAIRE DE HACHAGE ============
const HashManager = () => {
    const [hashInput, setHashInput] = useState('');
    const [hashResults, setHashResults] = useState({});
    const [selectedAlgorithm, setSelectedAlgorithm] = useState('SHA256');
    const [copied, setCopied] = useState(false);

    const hashAlgorithms = [
        { id: 'MD5', name: 'MD5', color: 'from-red-500 to-pink-500' },
        { id: 'SHA1', name: 'SHA-1', color: 'from-orange-500 to-red-500' },
        { id: 'SHA256', name: 'SHA-256', color: 'from-green-500 to-emerald-500' },
        { id: 'SHA512', name: 'SHA-512', color: 'from-blue-500 to-cyan-500' },
        { id: 'SHA3', name: 'SHA-3', color: 'from-purple-500 to-pink-500' }
    ];

    const computeHashes = (text) => {
        if (!text.trim()) {
            setHashResults({});
            return;
        }

        setHashResults({
            MD5: CryptoJS.MD5(text).toString(),
            SHA1: CryptoJS.SHA1(text).toString(),
            SHA256: CryptoJS.SHA256(text).toString(),
            SHA512: CryptoJS.SHA512(text).toString(),
            SHA3: CryptoJS.SHA3(text).toString()
        });
    };

    const copyToClipboard = (hash) => {
        navigator.clipboard.writeText(hash);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    return (
        <div className="space-y-6">
            <div className="glass-effect rounded-xl p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{color: 'var(--text-primary)'}}>
                    <Icons.Hash className="w-5 h-5" style={{color: 'var(--primary)'}} />
                    Calcul de Hachage
                </h3>
                
                <textarea
                    value={hashInput}
                    onChange={(e) => { setHashInput(e.target.value); computeHashes(e.target.value); }}
                    placeholder="Entrez le texte à hacher..."
                    className="w-full px-4 py-3 rounded-lg h-32 mb-4 border transition-colors"
                    style={{
                        backgroundColor: 'var(--bg-tertiary)',
                        color: 'var(--text-primary)',
                        borderColor: 'var(--border)'
                    }}
                />

                <div className="grid grid-cols-2 md:grid-cols-5 gap-2 mb-6">
                    {hashAlgorithms.map(algo => (
                        <button
                            key={algo.id}
                            onClick={() => setSelectedAlgorithm(algo.id)}
                            className={`py-2 px-3 rounded-lg font-medium text-sm transition-all ${
                                selectedAlgorithm === algo.id
                                    ? `bg-gradient-to-r ${algo.color} text-white shadow-lg`
                                    : 'hover:opacity-80'
                            }`}
                            style={selectedAlgorithm !== algo.id ? {
                                backgroundColor: 'var(--bg-tertiary)',
                                color: 'var(--text-secondary)'
                            } : {}}
                        >
                            {algo.name}
                        </button>
                    ))}
                </div>

                {hashInput && (
                    <div className="space-y-4 fade-in">
                        <div>
                            <label className="block mb-2 font-medium" style={{color: 'var(--primary)'}}>
                                Résultat {hashAlgorithms.find(a => a.id === selectedAlgorithm)?.name}
                            </label>
                            <div className="px-4 py-3 rounded-lg border-2 font-mono text-sm break-all"
                                 style={{
                                     backgroundColor: 'var(--bg-tertiary)',
                                     borderColor: 'var(--primary)',
                                     color: 'var(--text-primary)'
                                 }}>
                                {hashResults[selectedAlgorithm]}
                            </div>
                            <Button
                                variant={copied ? 'success' : 'outline'}
                                onClick={() => copyToClipboard(hashResults[selectedAlgorithm])}
                                icon={copied ? Icons.Check : Icons.Copy}
                                className="mt-2"
                            >
                                {copied ? 'Copié !' : 'Copier'}
                            </Button>
                        </div>

                        <div className="rounded-lg p-4" style={{backgroundColor: 'var(--bg-tertiary)'}}>
                            <h4 className="font-semibold mb-3" style={{color: 'var(--text-primary)'}}>Tous les hachages</h4>
                            <div className="space-y-2">
                                {Object.entries(hashResults).map(([algo, hash]) => (
                                    <div key={algo} className="flex items-center justify-between flex-wrap gap-2">
                                        <span className="text-sm" style={{color: 'var(--text-secondary)'}}>{algo}:</span>
                                        <code className="text-xs font-mono truncate max-w-xs" style={{color: 'var(--success)'}}>
                                            {hash}
                                        </code>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                )}
            </div>

            <div className="glass-effect rounded-xl p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{color: 'var(--text-primary)'}}>
                    <Icons.Alert className="w-5 h-5" style={{color: 'var(--info)'}} />
                    Information sur le Hachage
                </h3>
                <div className="space-y-3 text-sm" style={{color: 'var(--text-secondary)'}}>
                    <p><strong>Qu'est-ce que le hachage ?</strong></p>
                    <p>Le hachage transforme des données de taille variable en une chaîne de taille fixe. C'est unidirectionnel - impossible de retrouver les données originales.</p>
                    
                    <p><strong>Utilisations courantes :</strong></p>
                    <ul className="list-disc list-inside space-y-1 ml-2">
                        <li>Vérification d'intégrité de fichiers</li>
                        <li>Stockage sécurisé de mots de passe</li>
                        <li>Signatures digitales</li>
                        <li>Preuves de travail (Blockchain)</li>
                    </ul>
                </div>
            </div>
        </div>
    );
};

// ============ GESTIONNAIRE AES ============
const AESManager = () => {
    const [aesKey, setAesKey] = useState('');
    const [aesInput, setAesInput] = useState('');
    const [aesOutput, setAesOutput] = useState('');
    const [aesMode, setAesMode] = useState('encrypt');
    const [alert, setAlert] = useState(null);
    const fileInputRef = useRef(null);

    useEffect(() => {
        const savedKey = sessionStorage.getItem('aes_key');
        if (savedKey) {
            setAesKey(savedKey);
        }
    }, []);

    const generateAESKey = () => {
        const key = CryptoJS.lib.WordArray.random(32);
        const keyBase64 = CryptoJS.enc.Base64.stringify(key);
        setAesKey(keyBase64);
        sessionStorage.setItem('aes_key', keyBase64);
        setAlert({ type: 'success', message: 'Clé AES-256 générée avec succès ! N\'oubliez pas de l\'exporter.' });
    };

    const exportKey = () => {
        if (!aesKey) {
            setAlert({ type: 'error', message: 'Aucune clé à exporter' });
            return;
        }
        downloadFile(aesKey, 'aes_key.txt', 'text/plain');
        setAlert({ type: 'success', message: 'Clé exportée avec succès !' });
    };

    const importKey = async (event) => {
        const file = event.target.files[0];
        if (!file) return;

        try {
            const content = await readFile(file);
            const trimmedContent = content.trim();
            
            if (trimmedContent.length < 32) {
                throw new Error('Clé invalide');
            }
            
            setAesKey(trimmedContent);
            sessionStorage.setItem('aes_key', trimmedContent);
            setAlert({ type: 'success', message: 'Clé importée avec succès !' });
        } catch (error) {
            setAlert({ type: 'error', message: 'Erreur lors de l\'importation de la clé' });
        }
        
        event.target.value = '';
    };

    const clearKey = () => {
        if (confirm('Êtes-vous sûr de vouloir supprimer la clé ?')) {
            setAesKey('');
            sessionStorage.removeItem('aes_key');
            setAlert({ type: 'info', message: 'Clé supprimée' });
        }
    };

    const encryptAES = (text, key) => {
        try {
            const keyBytes = CryptoJS.enc.Base64.parse(key);
            const iv = CryptoJS.lib.WordArray.random(16);
            
            const encrypted = CryptoJS.AES.encrypt(text, keyBytes, {
                iv: iv,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7
            });
            
            const combined = iv.concat(encrypted.ciphertext);
            return CryptoJS.enc.Base64.stringify(combined);
        } catch (error) {
            throw new Error('Erreur de chiffrement AES');
        }
    };

    const decryptAES = (encryptedBase64, key) => {
        try {
            const keyBytes = CryptoJS.enc.Base64.parse(key);
            const combined = CryptoJS.enc.Base64.parse(encryptedBase64);
            
            const iv = CryptoJS.lib.WordArray.create(combined.words.slice(0, 4));
            const ciphertext = CryptoJS.lib.WordArray.create(combined.words.slice(4));
            
            const decrypted = CryptoJS.AES.decrypt(
                { ciphertext: ciphertext },
                keyBytes,
                {
                    iv: iv,
                    mode: CryptoJS.mode.CBC,
                    padding: CryptoJS.pad.Pkcs7
                }
            );
            
            return decrypted.toString(CryptoJS.enc.Utf8);
        } catch (error) {
            throw new Error('Erreur de déchiffrement AES');
        }
    };

    const handleAESProcess = () => {
        if (!aesKey) {
            setAlert({ type: 'error', message: 'Veuillez d\'abord générer ou importer une clé AES' });
            return;
        }

        if (!aesInput.trim()) {
            setAlert({ type: 'error', message: 'Veuillez entrer un message' });
            return;
        }

        try {
            if (aesMode === 'encrypt') {
                const encrypted = encryptAES(aesInput, aesKey);
                setAesOutput(encrypted);
                setAlert({ type: 'success', message: 'Message chiffré avec succès !' });
            } else {
                const decrypted = decryptAES(aesInput, aesKey);
                setAesOutput(decrypted);
                setAlert({ type: 'success', message: 'Message déchiffré avec succès !' });
            }
        } catch (error) {
            setAlert({ type: 'error', message: error.message });
        }
    };

    return (
        <div className="space-y-6">
            {alert && (
                <Alert type={alert.type} onClose={() => setAlert(null)}>
                    {alert.message}
                </Alert>
            )}

            <Alert type="warning">
                <strong>Important :</strong> Les clés sont stockées uniquement pour la session en cours. Exportez vos clés pour les réutiliser plus tard.
            </Alert>

            <div className="glass-effect rounded-xl p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{color: 'var(--text-primary)'}}>
                    <Icons.Cpu className="w-5 h-5" style={{color: 'var(--primary)'}} />
                    Gestion de la Clé AES-256
                </h3>
                
                <div className="space-y-4">
                    <div className="flex flex-wrap gap-2">
                        <Button onClick={generateAESKey} icon={Icons.Key}>
                            Générer Clé
                        </Button>
                        <Button 
                            onClick={exportKey} 
                            icon={Icons.Download}
                            variant="success"
                            disabled={!aesKey}
                        >
                            Exporter
                        </Button>
                        <div className="file-input-wrapper">
                            <Button 
                                onClick={() => fileInputRef.current?.click()}
                                icon={Icons.Upload}
                                variant="outline"
                            >
                                Importer
                            </Button>
                            <input
                                ref={fileInputRef}
                                type="file"
                                accept=".txt,.key"
                                onChange={importKey}
                            />
                        </div>
                        {aesKey && (
                            <Button 
                                onClick={clearKey}
                                icon={Icons.Trash}
                                variant="danger"
                            >
                                Supprimer
                            </Button>
                        )}
                    </div>

                    {aesKey && (
                        <div className="fade-in">
                            <label className="block mb-2 text-sm font-medium" style={{color: 'var(--success)'}}>
                                Clé AES-256 (Base64)
                            </label>
                            <div className="px-4 py-3 rounded-lg font-mono text-sm break-all border"
                                 style={{
                                     backgroundColor: 'var(--bg-tertiary)',
                                     borderColor: 'var(--success)',
                                     color: 'var(--text-primary)'
                                 }}>
                                {aesKey}
                            </div>
                            <p className="text-xs mt-2" style={{color: 'var(--text-muted)'}}>
                                Longueur: {aesKey.length} caractères
                            </p>
                        </div>
                    )}
                </div>
            </div>

            <div className="glass-effect rounded-xl p-6">
                <h3 className="text-lg font-semibold mb-4" style={{color: 'var(--text-primary)'}}>
                    {aesMode === 'encrypt' ? 'Chiffrement AES' : 'Déchiffrement AES'}
                </h3>
                
                <div className="flex gap-3 mb-4">
                    <Button
                        onClick={() => setAesMode('encrypt')}
                        variant={aesMode === 'encrypt' ? 'primary' : 'secondary'}
                        icon={Icons.Lock}
                        fullWidth
                    >
                        Chiffrer
                    </Button>
                    <Button
                        onClick={() => setAesMode('decrypt')}
                        variant={aesMode === 'decrypt' ? 'primary' : 'secondary'}
                        icon={Icons.Unlock}
                        fullWidth
                    >
                        Déchiffrer
                    </Button>
                </div>

                <textarea
                    value={aesInput}
                    onChange={(e) => setAesInput(e.target.value)}
                    placeholder={aesMode === 'encrypt' ? 'Message à chiffrer...' : 'Message chiffré (Base64)...'}
                    className="w-full px-4 py-3 rounded-lg h-32 mb-4 border transition-colors"
                    style={{
                        backgroundColor: 'var(--bg-tertiary)',
                        color: 'var(--text-primary)',
                        borderColor: 'var(--border)'
                    }}
                />

                <Button
                    onClick={handleAESProcess}
                    variant="primary"
                    fullWidth
                >
                    {aesMode === 'encrypt' ? 'Chiffrer avec AES' : 'Déchiffrer avec AES'}
                </Button>

                {aesOutput && (
                    <div className="mt-4 fade-in">
                        <label className="block mb-2 font-medium" style={{color: 'var(--primary)'}}>
                            {aesMode === 'encrypt' ? 'Message chiffré' : 'Message déchiffré'}
                        </label>
                        <div className="px-4 py-3 rounded-lg min-h-20 break-words border-2 font-mono text-sm"
                             style={{
                                 backgroundColor: 'var(--bg-tertiary)',
                                 borderColor: 'var(--primary)',
                                 color: 'var(--text-primary)'
                             }}>
                            {aesOutput}
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

// ============ GESTIONNAIRE RSA ============
const RSAManager = () => {
    const [rsaPrivateKey, setRsaPrivateKey] = useState('');
    const [rsaPublicKey, setRsaPublicKey] = useState('');
    const [rsaInput, setRsaInput] = useState('');
    const [rsaOutput, setRsaOutput] = useState('');
    const [rsaMode, setRsaMode] = useState('encrypt');
    const [rsaSignature, setRsaSignature] = useState('');
    const [alert, setAlert] = useState(null);
    const privateKeyInputRef = useRef(null);
    const publicKeyInputRef = useRef(null);

    useEffect(() => {
        const savedPrivate = sessionStorage.getItem('rsa_private_key');
        const savedPublic = sessionStorage.getItem('rsa_public_key');
        if (savedPrivate) setRsaPrivateKey(savedPrivate);
        if (savedPublic) setRsaPublicKey(savedPublic);
    }, []);

    const generateRSAKeys = () => {
        const crypt = new JSEncrypt({ default_key_size: "2048" });
        crypt.getKey();
        
        const privateKey = crypt.getPrivateKey();
        const publicKey = crypt.getPublicKey();
        
        setRsaPrivateKey(privateKey);
        setRsaPublicKey(publicKey);
        
        sessionStorage.setItem('rsa_private_key', privateKey);
        sessionStorage.setItem('rsa_public_key', publicKey);
        
        setAlert({ type: 'success', message: 'Paire de clés RSA-2048 générée ! N\'oubliez pas de les exporter.' });
    };

    const exportKeys = () => {
        if (!rsaPrivateKey || !rsaPublicKey) {
            setAlert({ type: 'error', message: 'Aucune clé à exporter' });
            return;
        }
        downloadFile(rsaPrivateKey, 'rsa_private_key.pem', 'application/x-pem-file');
        downloadFile(rsaPublicKey, 'rsa_public_key.pem', 'application/x-pem-file');
        setAlert({ type: 'success', message: 'Clés exportées avec succès !' });
    };

    const importPrivateKey = async (event) => {
        const file = event.target.files[0];
        if (!file) return;
        try {
            const content = await readFile(file);
            setRsaPrivateKey(content);
            sessionStorage.setItem('rsa_private_key', content);
            setAlert({ type: 'success', message: 'Clé privée importée !' });
        } catch (error) {
            setAlert({ type: 'error', message: 'Erreur d\'importation' });
        }
        event.target.value = '';
    };

    const importPublicKey = async (event) => {
        const file = event.target.files[0];
        if (!file) return;
        try {
            const content = await readFile(file);
            setRsaPublicKey(content);
            sessionStorage.setItem('rsa_public_key', content);
            setAlert({ type: 'success', message: 'Clé publique importée !' });
        } catch (error) {
            setAlert({ type: 'error', message: 'Erreur d\'importation' });
        }
        event.target.value = '';
    };

    const clearKeys = () => {
        if (confirm('Supprimer les clés ?')) {
            setRsaPrivateKey('');
            setRsaPublicKey('');
            sessionStorage.removeItem('rsa_private_key');
            sessionStorage.removeItem('rsa_public_key');
            setAlert({ type: 'info', message: 'Clés supprimées' });
        }
    };

    const encryptRSA = (text, publicKey) => {
        const crypt = new JSEncrypt();
        crypt.setPublicKey(publicKey);
        const encrypted = crypt.encrypt(text);
        if (!encrypted) throw new Error('Erreur de chiffrement RSA');
        return encrypted;
    };

    const decryptRSA = (encryptedBase64, privateKey) => {
        const crypt = new JSEncrypt();
        crypt.setPrivateKey(privateKey);
        const decrypted = crypt.decrypt(encryptedBase64);
        if (!decrypted) throw new Error('Erreur de déchiffrement RSA');
        return decrypted;
    };

    const signMessage = (message, privateKey) => {
        const crypt = new JSEncrypt();
        crypt.setPrivateKey(privateKey);
        const signature = crypt.sign(message, CryptoJS.SHA256, "sha256");
        if (!signature) throw new Error('Erreur de signature');
        return signature;
    };

    const verifySignature = (message, signature, publicKey) => {
        const crypt = new JSEncrypt();
        crypt.setPublicKey(publicKey);
        return crypt.verify(message, signature, CryptoJS.SHA256);
    };

    const handleRSAProcess = () => {
        try {
            if (rsaMode === 'encrypt') {
                if (!rsaPublicKey) throw new Error('Clé publique requise');
                if (!rsaInput.trim()) throw new Error('Message requis');
                const encrypted = encryptRSA(rsaInput, rsaPublicKey);
                setRsaOutput(encrypted);
                setAlert({ type: 'success', message: 'Message chiffré !' });
            } else if (rsaMode === 'decrypt') {
                if (!rsaPrivateKey) throw new Error('Clé privée requise');
                if (!rsaInput.trim()) throw new Error('Message chiffré requis');
                const decrypted = decryptRSA(rsaInput, rsaPrivateKey);
                setRsaOutput(decrypted);
                setAlert({ type: 'success', message: 'Message déchiffré !' });
            } else if (rsaMode === 'sign') {
                if (!rsaPrivateKey) throw new Error('Clé privée requise');
                if (!rsaInput.trim()) throw new Error('Message requis');
                const signature = signMessage(rsaInput, rsaPrivateKey);
                setRsaSignature(signature);
                setAlert({ type: 'success', message: 'Message signé !' });
            } else if (rsaMode === 'verify') {
                if (!rsaPublicKey) throw new Error('Clé publique requise');
                if (!rsaInput.trim() || !rsaSignature.trim()) throw new Error('Message et signature requis');
                const isValid = verifySignature(rsaInput, rsaSignature, rsaPublicKey);
                setRsaOutput(isValid ? 'Signature VALIDE' : 'Signature INVALIDE');
                setAlert({ type: isValid ? 'success' : 'error', message: isValid ? 'Signature valide !' : 'Signature invalide !' });
            }
        } catch (error) {
            setAlert({ type: 'error', message: error.message });
        }
    };

    return (
        <div className="space-y-6">
            {alert && <Alert type={alert.type} onClose={() => setAlert(null)}>{alert.message}</Alert>}
            <Alert type="warning"><strong>Important :</strong> Les clés sont stockées pour la session uniquement. Exportez-les !</Alert>

            <div className="glass-effect rounded-xl p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2" style={{color: 'var(--text-primary)'}}>
                    <Icons.FileKey className="w-5 h-5" style={{color: 'var(--primary)'}} />
                    Gestion des Clés RSA-2048
                </h3>
                
                <div className="space-y-4">
                    <div className="flex flex-wrap gap-2">
                        <Button onClick={generateRSAKeys} icon={Icons.Key}>Générer Paire</Button>
                        <Button onClick={exportKeys} icon={Icons.Download} variant="success" disabled={!rsaPrivateKey || !rsaPublicKey}>Exporter Tout</Button>
                        {(rsaPrivateKey || rsaPublicKey) && <Button onClick={clearKeys} icon={Icons.Trash} variant="danger">Supprimer Tout</Button>}
                    </div>

                    <div className="grid md:grid-cols-2 gap-4">
                        <div>
                            <label className="block mb-2 text-sm font-medium" style={{color: 'var(--success)'}}>Clé Publique</label>
                            {rsaPublicKey ? (
                                <div className="fade-in">
                                    <textarea value={rsaPublicKey} readOnly className="w-full px-4 py-2 rounded-lg h-32 text-sm font-mono border"
                                        style={{backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-primary)', borderColor: 'var(--success)'}} />
                                    <Button onClick={() => downloadFile(rsaPublicKey, 'rsa_public_key.pem')} icon={Icons.Download} variant="outline" className="text-xs mt-2">Exporter</Button>
                                </div>
                            ) : (
                                <div className="file-input-wrapper">
                                    <Button onClick={() => publicKeyInputRef.current?.click()} icon={Icons.Upload} variant="outline" fullWidth>Importer Clé Publique</Button>
                                    <input ref={publicKeyInputRef} type="file" accept=".pem,.key,.txt" onChange={importPublicKey} />
                                </div>
                            )}
                        </div>
                        <div>
                            <label className="block mb-2 text-sm font-medium" style={{color: 'var(--error)'}}>Clé Privée (Confidentielle)</label>
                            {rsaPrivateKey ? (
                                <div className="fade-in">
                                    <textarea value={rsaPrivateKey} readOnly className="w-full px-4 py-2 rounded-lg h-32 text-sm font-mono border"
                                        style={{backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-primary)', borderColor: 'var(--error)'}} />
                                    <Button onClick={() => downloadFile(rsaPrivateKey, 'rsa_private_key.pem')} icon={Icons.Download} variant="outline" className="text-xs mt-2">Exporter</Button>
                                </div>
                            ) : (
                                <div className="file-input-wrapper">
                                    <Button onClick={() => privateKeyInputRef.current?.click()} icon={Icons.Upload} variant="outline" fullWidth>Importer Clé Privée</Button>
                                    <input ref={privateKeyInputRef} type="file" accept=".pem,.key,.txt" onChange={importPrivateKey} />
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </div>

            <div className="glass-effect rounded-xl p-6">
                <h3 className="text-lg font-semibold mb-4" style={{color: 'var(--text-primary)'}}>
                    {rsaMode === 'encrypt' && 'Chiffrement RSA'}
                    {rsaMode === 'decrypt' && 'Déchiffrement RSA'}
                    {rsaMode === 'sign' && 'Signature RSA'}
                    {rsaMode === 'verify' && 'Vérification Signature'}
                </h3>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-4">
                    {[
                        { mode: 'encrypt', label: 'Chiffrer', icon: Icons.Lock },
                        { mode: 'decrypt', label: 'Déchiffrer', icon: Icons.Unlock },
                        { mode: 'sign', label: 'Signer', icon: Icons.FileKey },
                        { mode: 'verify', label: 'Vérifier', icon: Icons.Check }
                    ].map(({ mode, label, icon: Icon }) => (
                        <Button key={mode} onClick={() => setRsaMode(mode)} variant={rsaMode === mode ? 'primary' : 'secondary'} icon={Icon} fullWidth>{label}</Button>
                    ))}
                </div>

                <textarea value={rsaInput} onChange={(e) => setRsaInput(e.target.value)}
                    placeholder={rsaMode === 'encrypt' ? 'Message à chiffrer...' : rsaMode === 'decrypt' ? 'Message chiffré...' : 'Message à signer/vérifier...'}
                    className="w-full px-4 py-3 rounded-lg h-32 mb-4 border" style={{backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-primary)', borderColor: 'var(--border)'}} />

                {rsaMode === 'verify' && (
                    <textarea value={rsaSignature} onChange={(e) => setRsaSignature(e.target.value)} placeholder="Signature à vérifier..."
                        className="w-full px-4 py-3 rounded-lg h-20 mb-4 border" style={{backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-primary)', borderColor: 'var(--border)'}} />
                )}

                <Button onClick={handleRSAProcess} variant="primary" fullWidth>
                    {rsaMode === 'encrypt' && 'Chiffrer avec RSA'}
                    {rsaMode === 'decrypt' && 'Déchiffrer avec RSA'}
                    {rsaMode === 'sign' && 'Signer le message'}
                    {rsaMode === 'verify' && 'Vérifier la signature'}
                </Button>

                {(rsaOutput || (rsaSignature && rsaMode === 'sign')) && (
                    <div className="mt-4 space-y-4 fade-in">
                        {rsaOutput && (
                            <div>
                                <label className="block mb-2 font-medium" style={{color: 'var(--primary)'}}>
                                    {rsaMode === 'encrypt' && 'Message chiffré'}
                                    {rsaMode === 'decrypt' && 'Message déchiffré'}
                                    {rsaMode === 'verify' && 'Résultat'}
                                </label>
                                <div className="px-4 py-3 rounded-lg min-h-20 break-words border-2 font-mono text-sm"
                                     style={{backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--primary)', color: 'var(--text-primary)'}}>
                                    {rsaOutput}
                                </div>
                            </div>
                        )}
                        {rsaSignature && rsaMode === 'sign' && (
                            <div>
                                <label className="block mb-2 font-medium" style={{color: 'var(--primary)'}}>Signature générée</label>
                                <div className="px-4 py-3 rounded-lg min-h-20 break-words border-2 font-mono text-sm"
                                     style={{backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--primary)', color: 'var(--text-primary)'}}>
                                    {rsaSignature}
                                </div>
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
};

// ============ CRYPTOGRAPHIE CLASSIQUE ============
const ClassicCrypto = () => {
    const [mode, setMode] = useState('encrypt');
    const [algorithm, setAlgorithm] = useState('cesar');
    const [inputText, setInputText] = useState('');
    const [output, setOutput] = useState('');
    const [cesarKey, setCesarKey] = useState('');
    const [vigenereKey, setVigenereKey] = useState('');
    const [affineA, setAffineA] = useState('');
    const [affineB, setAffineB] = useState('');
    const [alert, setAlert] = useState(null);

    const letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

    const pgcd = (a, b) => { while (b !== 0) { let temp = b; b = a % b; a = temp; } return a; };
    const inverseModulaire = (a, m) => { for (let i = 1; i < m; i++) { if ((a * i) % m === 1) return i; } return null; };
    const estPremierAvec26 = (a) => pgcd(a, 26) === 1;

    const chiffrementCesar = (text, key) => {
        let result = '';
        for (let i = 0; i < text.length; i++) {
            const index = letters.indexOf(text[i]);
            if (index !== -1) {
                result += letters[(index + key) % 26];
            } else {
                result += text[i];
            }
        }
        return result;
    };

    const dechiffrementCesar = (text, key) => {
        let result = '';
        for (let i = 0; i < text.length; i++) {
            const index = letters.indexOf(text[i]);
            if (index !== -1) {
                result += letters[(index + 26 - key) % 26];
            } else {
                result += text[i];
            }
        }
        return result;
    };

    const chiffrementVigenere = (text, key) => {
        let result = '';
        let j = 0;
        for (let i = 0; i < text.length; i++) {
            const textIndex = letters.indexOf(text[i]);
            if (textIndex !== -1) {
                const keyIndex = letters.indexOf(key[j % key.length]);
                result += letters[(textIndex + keyIndex) % 26];
                j++;
            } else {
                result += text[i];
            }
        }
        return result;
    };

    const dechiffrementVigenere = (text, key) => {
        let result = '';
        let j = 0;
        for (let i = 0; i < text.length; i++) {
            const textIndex = letters.indexOf(text[i]);
            if (textIndex !== -1) {
                const keyIndex = letters.indexOf(key[j % key.length]);
                result += letters[(textIndex + 26 - keyIndex) % 26];
                j++;
            } else {
                result += text[i];
            }
        }
        return result;
    };

    const chiffrementAffine = (text, a, b) => {
        if (!estPremierAvec26(a)) return null;
        let result = '';
        for (let i = 0; i < text.length; i++) {
            const index = letters.indexOf(text[i]);
            if (index !== -1) {
                result += letters[(a * index + b) % 26];
            } else {
                result += text[i];
            }
        }
        return result;
    };

    const dechiffrementAffine = (text, a, b) => {
        if (!estPremierAvec26(a)) return null;
        const aInv = inverseModulaire(a, 26);
        if (aInv === null) return null;
        let result = '';
        for (let i = 0; i < text.length; i++) {
            const index = letters.indexOf(text[i]);
            if (index !== -1) {
                result += letters[(aInv * (index - b + 26)) % 26];
            } else {
                result += text[i];
            }
        }
        return result;
    };

    const handleProcess = () => {
        setAlert(null);
        if (!inputText.trim()) {
            setAlert({ type: 'error', message: 'Veuillez entrer un message' });
            return;
        }
        
        try {
            let result = '';
            if (mode === 'encrypt') {
                if (algorithm === 'cesar') {
                    if (!cesarKey) throw new Error('Clé César requise');
                    result = chiffrementCesar(inputText, parseInt(cesarKey));
                } else if (algorithm === 'vigenere') {
                    if (!vigenereKey) throw new Error('Clé Vigenère requise');
                    result = chiffrementVigenere(inputText, vigenereKey);
                } else if (algorithm === 'affine') {
                    if (!affineA || !affineB) throw new Error('Clés Affine (a et b) requises');
                    result = chiffrementAffine(inputText, parseInt(affineA), parseInt(affineB));
                    if (result === null) throw new Error(`${affineA} n'est pas premier avec 26. Valeurs valides: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25`);
                }
            } else {
                if (algorithm === 'cesar') {
                    if (!cesarKey) throw new Error('Clé César requise');
                    result = dechiffrementCesar(inputText, parseInt(cesarKey));
                } else if (algorithm === 'vigenere') {
                    if (!vigenereKey) throw new Error('Clé Vigenère requise');
                    result = dechiffrementVigenere(inputText, vigenereKey);
                } else if (algorithm === 'affine') {
                    if (!affineA || !affineB) throw new Error('Clés Affine (a et b) requises');
                    result = dechiffrementAffine(inputText, parseInt(affineA), parseInt(affineB));
                    if (result === null) throw new Error(`${affineA} n'est pas premier avec 26. Valeurs valides: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25`);
                }
            }
            setOutput(result);
            setAlert({ type: 'success', message: mode === 'encrypt' ? 'Message chiffré !' : 'Message déchiffré !' });
        } catch (error) {
            setAlert({ type: 'error', message: error.message });
            setOutput('');
        }
    };

    return (
        <div className="space-y-6">
            {alert && <Alert type={alert.type} onClose={() => setAlert(null)}>{alert.message}</Alert>}

            <div className="flex gap-4 mb-6">
                <Button onClick={() => setMode('encrypt')} variant={mode === 'encrypt' ? 'primary' : 'secondary'} icon={Icons.Lock} fullWidth>Chiffrement</Button>
                <Button onClick={() => setMode('decrypt')} variant={mode === 'decrypt' ? 'primary' : 'secondary'} icon={Icons.Unlock} fullWidth>Déchiffrement</Button>
            </div>

            <div className="glass-effect rounded-xl p-6 mb-6">
                <div className="flex items-center gap-2 mb-4">
                    <Icons.Key className="w-5 h-5" style={{color: 'var(--primary)'}} />
                    <h2 className="text-xl font-semibold" style={{color: 'var(--text-primary)'}}>Algorithme Classique</h2>
                </div>
                <div className="grid grid-cols-3 gap-3">
                    {['cesar', 'vigenere', 'affine'].map((algo) => (
                        <button key={algo} onClick={() => { setAlgorithm(algo); setAlert(null); }}
                            className={`py-3 px-4 rounded-lg font-medium transition-all ${algorithm === algo ? 'bg-gradient-to-r from-indigo-600 to-purple-600 text-white shadow-lg' : ''}`}
                            style={algorithm !== algo ? {backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', border: '1px solid var(--border)'} : {}}>
                            {algo === 'cesar' && 'César'}
                            {algo === 'vigenere' && 'Vigenère'}
                            {algo === 'affine' && 'Affine'}
                        </button>
                    ))}
                </div>
            </div>

            <div className="glass-effect rounded-xl p-6">
                <h2 className="text-xl font-semibold mb-4" style={{color: 'var(--text-primary)'}}>Configuration</h2>
                
                {algorithm === 'cesar' && (
                    <div className="mb-4">
                        <label className="block mb-2 font-medium" style={{color: 'var(--primary)'}}>Clé César</label>
                        <input type="number" value={cesarKey} onChange={(e) => setCesarKey(e.target.value)} className="w-full px-4 py-3 rounded-lg border"
                            placeholder="Décalage (ex: 3, 13)" style={{backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-primary)', borderColor: 'var(--border)'}} />
                    </div>
                )}

                {algorithm === 'vigenere' && (
                    <div className="mb-4">
                        <label className="block mb-2 font-medium" style={{color: 'var(--primary)'}}>Clé Vigenère</label>
                        <input type="text" value={vigenereKey} onChange={(e) => setVigenereKey(e.target.value)} className="w-full px-4 py-3 rounded-lg border"
                            placeholder="Clé texte (ex: WICE)" style={{backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-primary)', borderColor: 'var(--border)'}} />
                    </div>
                )}

                {algorithm === 'affine' && (
                    <div className="grid grid-cols-2 gap-4 mb-4">
                        <div>
                            <label className="block mb-2 font-medium" style={{color: 'var(--primary)'}}>Valeur 'a'</label>
                            <input type="number" value={affineA} onChange={(e) => setAffineA(e.target.value)} className="w-full px-4 py-3 rounded-lg border"
                                placeholder="ex: 5" style={{backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-primary)', borderColor: 'var(--border)'}} />
                        </div>
                        <div>
                            <label className="block mb-2 font-medium" style={{color: 'var(--primary)'}}>Valeur 'b'</label>
                            <input type="number" value={affineB} onChange={(e) => setAffineB(e.target.value)} className="w-full px-4 py-3 rounded-lg border"
                                placeholder="ex: 8" style={{backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-primary)', borderColor: 'var(--border)'}} />
                        </div>
                    </div>
                )}

                <div className="space-y-4">
                    <div>
                        <label className="block mb-2 font-medium" style={{color: 'var(--primary)'}}>
                            {mode === 'encrypt' ? 'Message clair' : 'Message chiffré'}
                        </label>
                        <textarea value={inputText} onChange={(e) => setInputText(e.target.value)} className="w-full px-4 py-3 rounded-lg h-32 border"
                            placeholder="Entrez votre message..." style={{backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-primary)', borderColor: 'var(--border)'}} />
                    </div>

                    <div className="flex gap-3">
                        <Button onClick={handleProcess} variant="primary" fullWidth>{mode === 'encrypt' ? 'Chiffrer' : 'Déchiffrer'}</Button>
                        <Button onClick={() => { setInputText(''); setOutput(''); setAlert(null); }} variant="secondary">Réinitialiser</Button>
                    </div>

                    {output && (
                        <div className="fade-in">
                            <label className="block mb-2 font-medium" style={{color: 'var(--primary)'}}>
                                {mode === 'encrypt' ? 'Message chiffré' : 'Message déchiffré'}
                            </label>
                            <div className="px-4 py-3 rounded-lg min-h-32 break-words border-2 font-mono"
                                 style={{backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--primary)', color: 'var(--text-primary)'}}>
                                {output}
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

// ============ APPLICATION PRINCIPALE ============
const CryptoApp = () => {
    const [activeTab, setActiveTab] = useState('classique');
    const [theme, setTheme] = useState('dark');

    useEffect(() => {
        const savedTheme = localStorage.getItem('theme') || 'dark';
        setTheme(savedTheme);
        document.documentElement.setAttribute('data-theme', savedTheme);
    }, []);

    const toggleTheme = () => {
        const newTheme = theme === 'dark' ? 'light' : 'dark';
        setTheme(newTheme);
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
    };

    const tabs = [
        { id: 'classique', name: 'Classique', color: 'from-purple-600 to-pink-600' },
        { id: 'symetrique', name: 'Moderne (AES)', color: 'from-blue-600 to-cyan-600' },
        { id: 'asymetrique', name: 'Asymétrique (RSA)', color: 'from-green-600 to-emerald-600' },
        { id: 'hachage', name: 'Hachage', color: 'from-indigo-600 to-purple-600' }
    ];

    return (
        <div className="min-h-screen p-4" style={{backgroundColor: 'var(--bg-primary)'}}>
            {/* Toggle Thème Soleil/Lune */}
            <button onClick={toggleTheme} className="theme-toggle" title={theme === 'dark' ? 'Mode Clair' : 'Mode Sombre'}>
                {theme === 'dark' ? <Icons.Sun className="w-6 h-6" /> : <Icons.Moon className="w-6 h-6" />}
            </button>

            <div className="max-w-6xl mx-auto">
                {/* En-tête */}
                <div className="text-center mb-8 pt-8">
                    <div className="inline-flex items-center justify-center gap-3 mb-4 gradient-bg px-8 py-3 rounded-full shadow-2xl">
                        <Icons.Shield className="w-8 h-8 text-white animate-pulse" />
                        <h1 className="text-3xl font-bold text-white">WiCE CTF 2025</h1>
                        <Icons.Key className="w-8 h-8 text-yellow-300 animate-pulse" />
                    </div>
                    <h2 className="text-2xl font-bold mb-2" style={{color: 'var(--text-primary)'}}>Panel Cryptographie</h2>
                    <p className="text-lg mb-1" style={{color: 'var(--secondary)'}}>Women in Cybersecurity Education</p>
                    <p style={{color: 'var(--text-muted)'}}>Capture The Flag - 1ère Édition</p>
                    
                    <div className="mt-4 inline-block glass-effect px-6 py-2 rounded-full">
                        <span style={{color: 'var(--text-secondary)'}} className="font-semibold">Cyber221 x WiCE x TDSI/LACGAA</span>
                    </div>
                </div>

                {/* Navigation par onglets */}
                <div className="glass-effect rounded-xl p-2 mb-6">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                        {tabs.map((tab) => (
                            <button
                                key={tab.id}
                                onClick={() => setActiveTab(tab.id)}
                                className={`py-3 px-4 rounded-lg font-semibold transition-all ${
                                    activeTab === tab.id ? `bg-gradient-to-r ${tab.color} text-white shadow-lg` : ''
                                }`}
                                style={activeTab !== tab.id ? {backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)'} : {}}
                            >
                                {tab.name}
                            </button>
                        ))}
                    </div>
                </div>

                {/* Contenu des onglets */}
                <div className="glass-effect rounded-xl p-6">
                    {activeTab === 'classique' && <ClassicCrypto />}
                    {activeTab === 'symetrique' && <AESManager />}
                    {activeTab === 'asymetrique' && <RSAManager />}
                    {activeTab === 'hachage' && <HashManager />}
                </div>

                {/* Pied de page */}
                <div className="text-center pb-8 mt-8" style={{color: 'var(--text-muted)'}}>
                    <p className="mb-4">Une initiative de la TDSI/LACGAA pour le programme Women in Cybersecurity Education</p>
                    <p className="text-sm mb-6">Cyber221 - WiCE CTF 2025 - TDSI/LACGAA</p>
                    
                    <div className="border-t pt-6 mt-6" style={{borderColor: 'var(--border)'}}>
                        <p className="font-semibold mb-3" style={{color: 'var(--secondary)'}}>Développé par :</p>
                        <div className="flex flex-col sm:flex-row items-center justify-center gap-4 sm:gap-8">
                            <a href="https://www.linkedin.com/in/ousmane-deme1618/" target="_blank" rel="noopener noreferrer"
                               className="flex items-center gap-2 hover:opacity-80 transition-opacity" style={{color: 'var(--text-secondary)'}}>
                                <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                                    <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
                                </svg>
                                <span className="font-medium">Ousmane DEME</span>
                            </a>
                            <span className="hidden sm:inline" style={{color: 'var(--border)'}}>•</span>
                            <a href="https://www.linkedin.com/in/serigne-fallou-thiam/" target="_blank" rel="noopener noreferrer"
                               className="flex items-center gap-2 hover:opacity-80 transition-opacity" style={{color: 'var(--text-secondary)'}}>
                                <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                                    <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
                                </svg>
                                <span className="font-medium">Serigne Fallou THIAM</span>
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

// Rendu React
ReactDOM.render(<CryptoApp />, document.getElementById('root'));