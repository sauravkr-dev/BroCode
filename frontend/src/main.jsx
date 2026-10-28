import React,{useEffect,useState} from 'react';
import{createRoot}from'react-dom/client';
import{ShieldCheck,Building2,FileCheck2,ClipboardList,Search,Plus,LogOut,RefreshCw,AlertTriangle,CheckCircle2,Clock3,UploadCloud,ArrowUpRight,LockKeyhole,Activity,FileText,MessageSquare,Users,Eye,Download,UserCheck,Trash2,RefreshCcw}from'lucide-react';
import'./style.css';

const DEMO={institution:['institution@example.com','DemoInstitution123!'],officer:['officer@example.com','DemoOfficer123!'],admin:['admin@example.com','DemoAdmin123!']};

function App(){
  const[token,setToken]=useState(localStorage.getItem('bc_token')||'');
  const[user,setUser]=useState(null);
  const[apps,setApps]=useState([]);
  const[selected,setSelected]=useState(null);
  const[detail,setDetail]=useState(null);
  const[summary,setSummary]=useState(null);
  const[error,setError]=useState('');
  const[successMsg,setSuccessMsg]=useState('');
  const[includeDrafts,setIncludeDrafts]=useState(false);
  const[busy,setBusy]=useState(false);
  const[login,setLogin]=useState({email:DEMO.institution[0],password:DEMO.institution[1]});
  const[form,setForm]=useState({institution_name:'',institution_code:'',application_type:'Extension of Approval',academic_year:'2026-27',programme:'',current_intake:'',proposed_intake:''});
  const[memo,setMemo]=useState('');
  const[reviewNote,setReviewNote]=useState('');
  const[reviewAction,setReviewAction]=useState('REVIEW_NOTE');
  const[correctionInstructions,setCorrectionInstructions]=useState('');
  const[findingRef,setFindingRef]=useState('');
  const[adminUsers,setAdminUsers]=useState([]);
  const[showAdminPanel,setShowAdminPanel]=useState(false);

  async function api(path,opts={}){
    const h={...(opts.headers||{})};
    if(token)h.Authorization=`Bearer ${token}`;
    if(opts.body&&!(opts.body instanceof FormData))h['Content-Type']='application/json';
    const r=await fetch(path,{...opts,headers:h});
    const data=await r.json().catch(()=>({detail:'Unexpected server response'}));
    if(!r.ok)throw Error(data.detail||`Request failed (${r.status})`);
    return data;
  }

  async function refresh(draftsFlag = includeDrafts){
    try{
      const me=await api('/api/auth/me');
      setUser(me);
      const appUrl = (me.role === 'admin' && draftsFlag) ? '/api/applications?include_drafts=true' : '/api/applications';
      const a=await api(appUrl);
      setApps(a);
      if(me.role!=='institution')setSummary(await api('/api/officer/summary'));
    }catch(e){setError(e.message);setToken('');localStorage.removeItem('bc_token')}
  }

  useEffect(()=>{if(token)refresh(includeDrafts)},[token, includeDrafts]);

  async function signIn(e){
    e.preventDefault();setBusy(true);setError('');setSuccessMsg('');
    try{
      const body=new URLSearchParams({username:login.email,password:login.password});
      const r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body});
      const d=await r.json();
      if(!r.ok)throw Error(d.detail||'Login failed');
      localStorage.setItem('bc_token',d.access_token);
      setToken(d.access_token);
    }catch(e){setError(e.message)}finally{setBusy(false)}
  }

  async function openApp(a){
    setSelected(a);setDetail(null);setMemo('');setReviewNote('');setCorrectionInstructions('');setFindingRef('');setError('');
    try{setDetail(await api(`/api/applications/${a.id}`))}catch(e){setError(e.message)}
  }

  async function createApp(e){
    e.preventDefault();setBusy(true);setError('');setSuccessMsg('');
    try{
      const d=await api('/api/applications',{method:'POST',body:JSON.stringify({...form,current_intake:form.current_intake===''?null:Number(form.current_intake),proposed_intake:form.proposed_intake===''?null:Number(form.proposed_intake)})});
      setForm({institution_name:'',institution_code:'',application_type:'Extension of Approval',academic_year:'2026-27',programme:'',current_intake:'',proposed_intake:''});
      setSuccessMsg(`Draft application #${d.id} created successfully.`);
      await refresh();await openApp(d);
    }catch(e){setError(e.message)}finally{setBusy(false)}
  }

  async function deleteDraft(appId = selected?.id){
    if(!appId)return;
    const ok = window.confirm(
      "Are you sure you want to permanently delete this draft application?\n\nAll uploaded files, draft screening findings, and application data will be permanently removed. This action cannot be undone."
    );
    if(!ok)return;
    setBusy(true);setError('');setSuccessMsg('');
    try{
      const res = await api(`/api/applications/${appId}`, {method:'DELETE'});
      setSuccessMsg(res.message || 'Draft application deleted successfully.');
      setSelected(null);
      setDetail(null);
      await refresh();
    }catch(e){setError(e.message)}finally{setBusy(false)}
  }

  async function upload(e){
    const f=e.target.files?.[0];if(!f||!selected)return;
    setBusy(true);setError('');setSuccessMsg('');
    try{
      const fd=new FormData();fd.append('file',f);
      const res = await api(`/api/applications/${selected.id}/documents`,{method:'POST',body:fd});
      setSuccessMsg(`Document '${res.filename}' uploaded and pre-screened.`);
      await openApp(selected);await refresh();
    }catch(e){setError(e.message)}finally{setBusy(false);e.target.value=''}
  }

  async function removeDoc(doc){
    if(!selected || !doc)return;
    const ok = window.confirm(
      `Are you sure you want to remove '${doc.original_name}'?\n\nThis will safely remove the file and delete obsolete screening findings associated with it.`
    );
    if(!ok)return;
    setBusy(true);setError('');setSuccessMsg('');
    try{
      const res = await api(`/api/applications/${selected.id}/documents/${doc.id}`, {method:'DELETE'});
      setSuccessMsg(res.message || 'Document removed successfully.');
      await openApp(selected);
      await refresh();
    }catch(e){setError(e.message)}finally{setBusy(false)}
  }

  async function replaceDoc(docId, e){
    const f = e.target.files?.[0];
    if(!f || !selected || !docId)return;
    setBusy(true);setError('');setSuccessMsg('');
    try{
      const fd = new FormData();
      fd.append('file', f);
      const res = await api(`/api/applications/${selected.id}/documents/${docId}`, {
        method:'PUT',
        body:fd,
      });
      setSuccessMsg(res.message || 'Document replaced and re-screened successfully.');
      await openApp(selected);
      await refresh();
    }catch(e){setError(e.message)}finally{setBusy(false);e.target.value=''}
  }

  async function uploadOfficerEvidence(e){
    const f=e.target.files?.[0];if(!f||!selected)return;
    setBusy(true);setError('');setSuccessMsg('');
    try{
      const fd=new FormData();fd.append('file',f);
      await api(`/api/applications/${selected.id}/officer-evidence`,{method:'POST',body:fd});
      setSuccessMsg("Officer evidence attached and labeled separately.");
      await openApp(selected);await refresh();
    }catch(e){setError(e.message)}finally{setBusy(false);e.target.value=''}
  }

  async function downloadDoc(d){
    try{
      const res=await fetch(`/api/applications/${selected.id}/documents/${d.id}/download`,{
        headers:{Authorization:`Bearer ${token}`}
      });
      if(!res.ok)throw new Error('Download failed: unauthorized or missing document');
      const blob=await res.blob();
      const url=window.URL.createObjectURL(blob);
      const a=document.createElement('a');
      a.href=url;
      a.download=d.original_name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    }catch(e){setError(e.message)}
  }

  async function changeStatus(status){
    setBusy(true);setError('');setSuccessMsg('');
    try{
      await api(`/api/applications/${selected.id}/status`,{method:'PATCH',body:JSON.stringify({status})});
      setSuccessMsg(`Application status updated to ${status.replaceAll('_',' ')}.`);
      await refresh();
      const a=apps.find(x=>x.id===selected.id)||selected;
      await openApp({...a,status});
    }catch(e){setError(e.message)}finally{setBusy(false)}
  }

  async function claimApp(){
    try{
      await api(`/api/applications/${selected.id}/assign`,{method:'PATCH',body:JSON.stringify({officer_id:user.id})});
      await refresh();
      await openApp(selected);
    }catch(e){setError(e.message)}
  }

  async function submitReview(){
    if(!reviewNote.trim())return;
    setBusy(true);
    try{
      const refs = findingRef.split(',').map(s=>s.trim()).filter(Boolean);
      await api(`/api/applications/${selected.id}/reviews`,{
        method:'POST',
        body:JSON.stringify({
          action:reviewAction,
          notes:reviewNote,
          finding_references:refs,
          correction_instructions:correctionInstructions,
        })
      });
      setReviewNote('');setCorrectionInstructions('');setFindingRef('');
      await openApp(selected);
    }catch(e){setError(e.message)}finally{setBusy(false)}
  }

  async function generateMemo(){
    try{const d=await api(`/api/applications/${selected.id}/memo`,{method:'POST'});setMemo(d.memo)}catch(e){setError(e.message)}
  }

  async function loadAdminUsers(){
    try{const u=await api('/api/admin/users');setAdminUsers(u);setShowAdminPanel(true)}catch(e){setError(e.message)}
  }

  function logout(){setToken('');setUser(null);setSelected(null);setDetail(null);setShowAdminPanel(false);localStorage.removeItem('bc_token')}

  // --- Login Screen ---
  if(!token||!user)return <main className="login-shell"><section className="login-hero"><div className="brand"><span className="brand-icon"><ShieldCheck/></span><span>BroCode<span className="dot">.</span></span></div><div className="hero-copy"><div className="eyebrow">SIH 26261 · REGULATORY TECHNOLOGY</div><h1>Compliance clarity.<br/><em>Evidence first.</em></h1><p>AI-assisted application pre-screening for institutions and compliance teams — with traceable findings and human-led decisions.</p><div className="hero-points"><span><CheckCircle2/> Evidence-linked checks</span><span><LockKeyhole/> Role-based workspaces</span><span><Activity/> Audit-aware workflow</span></div></div><div className="hero-foot">DEMO ENVIRONMENT <span>•</span> NOT AN OFFICIAL AICTE PORTAL</div></section><section className="login-panel"><form className="login-card" onSubmit={signIn}><div className="mini-icon"><LockKeyhole/></div><div className="eyebrow">SECURE WORKSPACE</div><h2>Welcome back</h2><p className="muted">Sign in to your compliance workspace.</p>{error&&<div className="error">{error}</div>}<label>Email address<input type="email" required value={login.email} onChange={e=>setLogin({...login,email:e.target.value})}/></label><label>Password<input type="password" required value={login.password} onChange={e=>setLogin({...login,password:e.target.value})}/></label><button className="primary full" disabled={busy}>{busy?'Signing in…':'Sign in securely'} <ArrowUpRight size={17}/></button><div className="demo-box"><strong>Demo accounts</strong><div className="demo-buttons">{Object.entries(DEMO).map(([role,v])=><button type="button" key={role} onClick={()=>setLogin({email:v[0],password:v[1]})}>{role}</button>)}</div><small>Demo users only. Change credentials before deployment.</small></div></form></section></main>;

  const currentStatus = detail?.application?.status || selected?.status || 'DRAFT';
  const isInstitution = user.role === 'institution';
  const isOfficer = user.role === 'officer';
  const isAdmin = user.role === 'admin';
  const isOfficerOrAdmin = isOfficer || isAdmin;
  const isAssignedOfficer = isOfficerOrAdmin && (isAdmin || detail?.application?.assigned_officer_id === user.id);
  const institutionDocs = (detail?.documents || []).filter(d => d.upload_type !== 'officer_evidence');
  const officerDocs = (detail?.documents || []).filter(d => d.upload_type === 'officer_evidence');
  const activeDeficiency = detail?.reviews?.find(r => r.action === 'DEFICIENCY_REQUEST');

  // --- Main App Shell ---
  return <div className="app-shell"><aside className="sidebar"><div className="brand"><span className="brand-icon"><ShieldCheck/></span><span>BroCode<span className="dot">.</span></span></div><div className="workspace-label">WORKSPACE</div>
  <div className={`nav-item ${!showAdminPanel?'active':''}`} onClick={()=>setShowAdminPanel(false)} style={{cursor:'pointer'}}><ClipboardList size={18}/> Applications</div>
  {isOfficerOrAdmin&&<div className="nav-item"><Activity size={18}/> Officer overview</div>}
  {isAdmin&&<div className={`nav-item ${showAdminPanel?'active':''}`} onClick={loadAdminUsers} style={{cursor:'pointer'}}><Users size={18}/> User management</div>}
  <div className="side-note"><div className="side-note-icon"><ShieldCheck/></div><strong>Evidence-first review</strong><p>Automated checks support human scrutiny. They never replace an authorized decision.</p></div>
  <div className="sidebar-bottom"><span className="avatar">{user.name?.[0]||'B'}</span><div className="user-label"><strong>{user.name}</strong><small>{user.role} access</small></div><button className="icon-btn" title="Sign out" onClick={logout}><LogOut size={17}/></button></div></aside>

  <main className="main"><header className="topbar"><div><span className="crumb">Compliance workspace</span><span className="slash"> / </span><strong>{showAdminPanel?'User Management':selected?`Application #${selected.id}`:'Applications'}</strong></div><div className="top-actions"><span className="env-pill"><span/> DEMO ENVIRONMENT</span><button className="icon-btn" onClick={refresh} title="Refresh"><RefreshCw size={17}/></button></div></header>
  <div className="content">

  {/* ========== ADMIN USER MANAGEMENT ========== */}
  {showAdminPanel&&isAdmin&&<>
    <div className="page-heading"><div><div className="eyebrow">ADMIN PANEL</div><h1>User Management</h1><p>Manage system users, roles, and access.</p></div><div className="heading-actions"><button className="secondary" onClick={()=>setShowAdminPanel(false)}>Back to applications</button></div></div>
    <section className="panel"><div className="panel-heading"><div><h2>Registered Users</h2><p>All users in the system</p></div><span className="count-pill">{adminUsers.length} users</span></div>
    <div className="table-wrap"><table><thead><tr><th>ID</th><th>EMAIL</th><th>NAME</th><th>ROLE</th><th>ACTIVE</th></tr></thead><tbody>
    {adminUsers.map(u=><tr key={u.id}><td>{u.id}</td><td>{u.email}</td><td>{u.name}</td><td><span className={`status ${u.role==='admin'?'review':u.role==='officer'?'submitted':'draft'}`}><i/>{u.role}</span></td><td>{u.active?<span style={{color:'#23895a'}}>✓ Active</span>:<span style={{color:'#c04848'}}>✗ Inactive</span>}</td></tr>)}
    </tbody></table></div></section>
  </>}

  {/* ========== MAIN APPLICATION VIEW ========== */}
  {!showAdminPanel&&<>
  <div className="page-heading"><div><div className="eyebrow">{isInstitution?'INSTITUTION PORTAL':isAdmin?'ADMIN OVERVIEW':'OFFICER REVIEW DESK'}</div><h1>{selected?selected.institution_name:'Application overview'}</h1><p>{selected?`Application #${selected.id} · ${selected.academic_year}`:'Track submissions, review screening signals, and keep every finding auditable.'}</p></div><div className="heading-actions">{selected&&<button className="secondary" onClick={()=>{setSelected(null);setDetail(null);setError('');setSuccessMsg('')}}>Back to list</button>}{isInstitution&&selected&&currentStatus==='DRAFT'&&<button className="secondary" onClick={()=>deleteDraft(selected.id)} disabled={busy} title="Permanently delete this draft application" style={{color:'#c04848',borderColor:'#ffd6d6',background:'#fff5f5'}}><Trash2 size={15}/> Delete draft</button>}{isInstitution&&!selected&&<button className="primary" onClick={()=>document.getElementById('new-app').scrollIntoView({behavior:'smooth'})}><Plus size={17}/> New application</button>}</div></div>

  {error&&<div className="error banner">{error}<button onClick={()=>setError('')}>Dismiss</button></div>}
  {successMsg&&<div className="banner" style={{background:'#edfcf2',border:'1px solid #a3e6b9',color:'#1e6b37',padding:'10px 14px',borderRadius:'8px',marginBottom:'14px',fontSize:'12px',display:'flex',justifyContent:'space-between',alignItems:'center'}}><span>✓ {successMsg}</span><button onClick={()=>setSuccessMsg('')} style={{border:0,background:'none',color:'#1e6b37',cursor:'pointer',fontWeight:600}}>✕</button></div>}

  {/* --- Application List --- */}
  {!selected&&<><div className="stat-grid"><Stat icon={<FileText/>} label="Total applications" value={summary?.total_applications??apps.length} sub="All accessible records"/><Stat icon={<Clock3/>} label="Under review" value={apps.filter(a=>['UNDER_REVIEW','RECTIFICATION_SUBMITTED'].includes(a.status)).length} sub="Awaiting scrutiny"/><Stat icon={<AlertTriangle/>} label="Deficiency raised" value={apps.filter(a=>a.status==='DEFICIENCY_RAISED').length} sub="Action may be needed"/><Stat icon={<CheckCircle2/>} label="Closed" value={apps.filter(a=>a.status==='CLOSED').length} sub="Workflow closed"/></div>
  <section className="panel"><div className="panel-heading"><div><h2>Applications</h2><p>Open a record to view documents and screening findings.</p></div><div style={{display:'flex',gap:'12px',alignItems:'center'}}>{isAdmin&&<label style={{display:'inline-flex',alignItems:'center',gap:'6px',fontSize:'11px',color:'#4a5568',cursor:'pointer'}}><input type="checkbox" checked={includeDrafts} onChange={e=>setIncludeDrafts(e.target.checked)}/> Include Drafts (Oversight View)</label>}<div className="search-box"><Search size={16}/><span>Search coming soon</span></div></div></div>
  {apps.length===0?<div className="empty"><div className="empty-icon"><Building2/></div><h3>No applications yet</h3><p>Create an application to begin document pre-screening.</p></div>:
  <div className="table-wrap"><table><thead><tr><th>INSTITUTION</th><th>APPLICATION TYPE</th><th>ACADEMIC YEAR</th><th>CYCLE</th><th>ASSIGNED OFFICER</th><th>STATUS</th><th></th></tr></thead><tbody>
  {apps.map(a=><tr key={a.id}><td><div className="inst"><span className="inst-icon"><Building2 size={17}/></span><span><strong>{a.institution_name}</strong><small>{a.institution_code||`Application #${a.id}`}</small></span></div></td><td>{a.application_type}</td><td>{a.academic_year}</td><td><span className="count-pill">v{a.submission_version||1}</span></td><td>{a.assigned_officer_id?<span style={{fontSize:'10px',color:'#3a4d70'}}><UserCheck size={13}/> Officer #{a.assigned_officer_id}</span>:<span style={{fontSize:'10px',color:'#97a1b2'}}>Unassigned</span>}</td><td><Status value={a.status}/></td><td><div style={{display:'flex',gap:'6px',alignItems:'center',justifyContent:'flex-end'}}><button className="row-link" onClick={()=>openApp(a)}>Review <ArrowUpRight size={15}/></button>{isInstitution&&a.status==='DRAFT'&&<button className="row-link" onClick={(e)=>{e.stopPropagation();deleteDraft(a.id)}} title="Delete draft application" style={{color:'#c04848'}}><Trash2 size={14}/></button>}</div></td></tr>)}
  </tbody></table></div>}
  </section>

  {/* --- Create Application (Institution only) --- */}
  {isInstitution&&<section className="panel create-panel" id="new-app"><div className="panel-heading"><div><h2>Create application</h2><p>Enter the institution and programme details to start a screening record.</p></div><span className="step-badge">STEP 01</span></div><form className="form-grid" onSubmit={createApp}><label className="wide">Institution name *<input required minLength="2" value={form.institution_name} onChange={e=>setForm({...form,institution_name:e.target.value})} placeholder="Enter official institution name"/></label><label>Institution code<input value={form.institution_code} onChange={e=>setForm({...form,institution_code:e.target.value})} placeholder="If applicable"/></label><label>Application type<select value={form.application_type} onChange={e=>setForm({...form,application_type:e.target.value})}><option>Extension of Approval</option><option>New Institution</option><option>Introduction of Programme</option><option>Change in Intake</option><option>Other / Needs classification</option></select></label><label>Academic year<select value={form.academic_year} onChange={e=>setForm({...form,academic_year:e.target.value})}><option>2026-27</option><option>2025-26</option><option>2024-25</option></select></label><label>Programme / course<input value={form.programme} onChange={e=>setForm({...form,programme:e.target.value})} placeholder="e.g. Engineering and Technology"/></label><label>Current approved intake<input type="number" min="0" value={form.current_intake} onChange={e=>setForm({...form,current_intake:e.target.value})}/></label><label>Proposed intake<input type="number" min="0" value={form.proposed_intake} onChange={e=>setForm({...form,proposed_intake:e.target.value})}/></label><div className="wide form-bottom"><span>Rules remain illustrative until officially mapped and approved.</span><button className="primary" disabled={busy}>Create draft <ArrowUpRight size={16}/></button></div></form></section>}
  </>}

  {/* --- Application Detail --- */}
  {selected&&<>
  <div className="detail-grid"><section className="panel"><div className="panel-heading"><div><h2>Application details</h2><p>Institution-submitted information</p></div><div style={{display:'flex',gap:'8px',alignItems:'center'}}>{isOfficerOrAdmin&&!detail?.application?.assigned_officer_id&&<button className="secondary" onClick={claimApp}><UserCheck size={14}/> Claim assignment</button>}<Status value={currentStatus}/></div></div><div className="detail-fields"><Field label="Institution code" value={detail?.application?.institution_code||'Not provided'}/><Field label="Application type" value={detail?.application?.application_type}/><Field label="Academic year" value={detail?.application?.academic_year}/><Field label="Submission Version" value={`Cycle v${detail?.application?.submission_version||1}`}/><Field label="Assigned Officer" value={detail?.application?.assigned_officer_id?`Officer #${detail.application.assigned_officer_id}`:'Unassigned'}/><Field label="Programme / course" value={detail?.application?.programme||'Not provided'}/><Field label="Current intake" value={detail?.application?.current_intake??'Not provided'}/><Field label="Proposed intake" value={detail?.application?.proposed_intake??'Not provided'}/></div></section>
  <section className="panel risk-panel"><div className="eyebrow">SCREENING TRIAGE</div><div className="risk-number">{detail?.risk_score??'—'}<small>/100</small></div><div className="risk-label">Heuristic review score</div><div className="risk-track"><span style={{width:`${detail?.risk_score||0}%`}}/></div><p>Not a probability of fraud and not an approval decision. Scores prioritize manual review only.</p><div className="manual-flag"><AlertTriangle size={17}/> Issuer verification not configured</div></section></div>

  {/* --- Institution: Deficiency Notice & Instructions --- */}
  {isInstitution&&currentStatus==='DEFICIENCY_RAISED'&&activeDeficiency&&(
    <section className="panel" style={{borderLeft:'4px solid #b55c2c'}}>
      <div className="panel-heading"><div><h2 style={{color:'#b55c2c'}}>Officer Deficiency Notice</h2><p>Review the officer observations and complete required rectifications</p></div><span className="count-pill" style={{background:'#fff0e8',color:'#b55c2c'}}>Deficiency Action Required</span></div>
      <div style={{padding:'16px 20px'}}>
        <div style={{marginBottom:'10px'}}><strong>Officer Observations:</strong><p style={{fontSize:'12px',color:'#35425e',margin:'4px 0'}}>{activeDeficiency.notes}</p></div>
        {activeDeficiency.correction_instructions&&<div style={{marginBottom:'10px'}}><strong>Correction Instructions:</strong><p style={{fontSize:'12px',color:'#35425e',margin:'4px 0'}}>{activeDeficiency.correction_instructions}</p></div>}
        {activeDeficiency.finding_references?.length>0&&<div><strong style={{fontSize:'10px',color:'#71809e',textTransform:'uppercase'}}>Cited Findings:</strong><div style={{display:'flex',gap:'6px',marginTop:'4px'}}>{activeDeficiency.finding_references.map(ref=><span key={ref} className="count-pill" style={{background:'#fff0e8',color:'#b55c2c'}}>{ref}</span>)}</div></div>}
      </div>
    </section>
  )}

  {/* --- Submission Version History --- */}
  {detail?.submission_history?.length>0&&<section className="panel"><div className="panel-heading"><div><h2>Submission history</h2><p>Auditable version history of submissions and rectifications.</p></div><span className="count-pill">{detail.submission_history.length} cycles</span></div>
  <div className="doc-list">{detail.submission_history.map(sh=><div className="doc-row" key={sh.version}><div className="doc-icon"><FileCheck2 size={17}/></div><div className="doc-info"><strong>{sh.stage} (Cycle v{sh.version})</strong><small>{sh.documents_count} document(s) uploaded in this submission cycle</small></div></div>)}</div>
  </section>}

  {/* --- Institution Documents --- */}
  <section className="panel"><div className="panel-heading"><div><h2>Institution documents</h2><p>PDF, PNG, JPEG or WebP · Maximum 12 MB per file</p></div>
  {isInstitution&&(currentStatus==='DRAFT'||currentStatus==='DEFICIENCY_RAISED'||currentStatus==='RECTIFICATION_SUBMITTED')&&<label className="upload-btn"><UploadCloud size={17}/> Upload document<input type="file" accept="application/pdf,image/png,image/jpeg,image/webp" onChange={upload} disabled={busy}/></label>}
  </div>
  {institutionDocs.length===0?<div className="upload-empty"><UploadCloud/><strong>No documents uploaded</strong><span>Upload a file to run local extraction and screening checks.</span></div>:
  <div className="doc-list">{institutionDocs.map(d=><div className="doc-row" key={d.id}>
    <div className="doc-icon"><FileText/></div>
    <div className="doc-info">
      <strong>{d.original_name}</strong>
      <small>{d.doc_type} · v{d.submission_version||1} · {d.text_characters} chars · SHA-256 {d.sha256.slice(0,14)}… · {d.created_at?new Date(d.created_at).toLocaleDateString():''}</small>
    </div>
    <div style={{display:'flex',alignItems:'center',gap:'6px',flexWrap:'wrap'}}>
      <button className="row-link" onClick={()=>downloadDoc(d)} title="Download document"><Download size={14}/> Download</button>
      {isInstitution&&(currentStatus==='DRAFT'||currentStatus==='DEFICIENCY_RAISED')&&(
        <>
          <label className="row-link" style={{cursor:'pointer',display:'inline-flex',alignItems:'center',gap:'4px'}} title="Replace this document with a corrected file">
            <RefreshCcw size={13}/> Replace
            <input type="file" accept="application/pdf,image/png,image/jpeg,image/webp" style={{display:'none'}} onChange={e=>replaceDoc(d.id, e)} disabled={busy}/>
          </label>
          <button className="row-link" onClick={()=>removeDoc(d)} title="Remove document" style={{color:'#c04848'}}>
            <Trash2 size={13}/> Remove
          </button>
        </>
      )}
      {isInstitution&&!['DRAFT','DEFICIENCY_RAISED'].includes(currentStatus)&&(
        <span style={{fontSize:'10px',color:'#8490a6',fontStyle:'italic',padding:'0 4px'}}>Locked during review</span>
      )}
      <span className="manual-tag">{d.verification_status==='MANUAL_VERIFICATION_REQUIRED'?'Manual verification':d.verification_status}</span>
    </div>
  </div>)}</div>}
  </section>

  {/* --- Officer Evidence (separate from institution docs) --- */}
  {isOfficerOrAdmin&&<section className="panel"><div className="panel-heading"><div><h2>Officer evidence attachments</h2><p>Evidence uploaded by reviewing officers — separate from institution documents.</p></div>
  {isAssignedOfficer&&<label className="upload-btn"><Eye size={17}/> Attach evidence<input type="file" accept="application/pdf,image/png,image/jpeg,image/webp" onChange={uploadOfficerEvidence} disabled={busy}/></label>}
  </div>
  {officerDocs.length===0?<div className="upload-empty"><Eye/><strong>No officer evidence attached</strong><span>Attach supporting evidence for your review.</span></div>:
  <div className="doc-list">{officerDocs.map(d=><div className="doc-row" key={d.id}><div className="doc-icon" style={{background:'#fff5e7',color:'#b47b2b'}}><Eye/></div><div className="doc-info"><strong>{d.original_name}</strong><small>Officer Evidence · {d.created_at?new Date(d.created_at).toLocaleDateString():''}</small></div><button className="row-link" onClick={()=>downloadDoc(d)} title="Download evidence" style={{marginRight:'10px'}}><Download size={14}/> Download</button><span className="manual-tag" style={{background:'#edf1ff',color:'#5666df'}}>Officer evidence</span></div>)}</div>}
  </section>}

  {/* --- Screening Findings --- */}
  <section className="panel"><div className="panel-heading"><div><h2>Screening findings</h2><p>Each finding includes a reason and source label.</p></div><span className="count-pill">{detail?.findings?.length||0} findings</span></div>
  {!detail?.findings?.length?<div className="empty compact"><p>Findings appear after a document is screened.</p></div>:
  <div className="finding-list">{detail.findings.map(f=><div className="finding" key={f.id}><div className={`finding-icon ${['PASS','VERIFIED'].includes(f.result)?'good':['FAIL','FAILED_CHECK'].includes(f.result)?'bad':'warn'}`}>{['PASS','VERIFIED'].includes(f.result)?<CheckCircle2/>:<AlertTriangle/>}</div><div className="finding-body"><div className="finding-title"><strong>{f.rule_id}</strong>{f.document_id&&<small style={{color:'#98a2b3'}}>Doc #{f.document_id}</small>}<span className={`result ${f.result.toLowerCase()}`}>{f.result.replaceAll('_',' ')}</span><span className={`severity ${f.severity}`}>{f.severity}</span></div><p>{f.message}</p><small>Source: {f.source_reference}</small></div></div>)}</div>}
  </section>

  {/* --- Institution: Submit or Discard Draft --- */}
  {isInstitution&&currentStatus==='DRAFT'&&(
    <section className="panel"><div className="panel-heading"><div><h2>Submit or discard draft</h2><p>Submit for official compliance review once all documents are uploaded, or discard this draft.</p></div></div>
    <div className="action-row" style={{display:'flex',gap:'12px',alignItems:'center'}}>
      <button className="primary" onClick={()=>changeStatus('UNDER_REVIEW')} disabled={busy}>Submit for review <ArrowUpRight size={16}/></button>
      <button type="button" className="secondary" onClick={()=>deleteDraft(selected.id)} disabled={busy} style={{color:'#c04848',borderColor:'#ffd6d6',background:'#fff5f5'}}><Trash2 size={15}/> Delete draft</button>
    </div>
    </section>
  )}

  {/* --- Institution: Submit Rectification --- */}
  {isInstitution&&currentStatus==='DEFICIENCY_RAISED'&&<section className="panel"><div className="panel-heading"><div><h2>Respond to deficiency</h2><p>Upload corrected documents above, then submit your rectification cycle.</p></div></div><div className="action-row"><button className="primary" onClick={()=>changeStatus('RECTIFICATION_SUBMITTED')}>Submit rectification cycle <ArrowUpRight size={16}/></button></div></section>}

  {/* --- Officer Actions --- */}
  {isOfficerOrAdmin&&<section className="panel"><div className="panel-heading"><div><h2>Officer actions</h2><p>{isAssignedOfficer?'Workflow transitions are logged. This does not grant AICTE approval.':'Read-only mode. Claim assignment to record reviews or change application status.'}</p></div></div><div className="action-row">
  {isAssignedOfficer&&<>
    {currentStatus==='DRAFT'&&<button className="secondary" onClick={()=>changeStatus('UNDER_REVIEW')}>Start review</button>}
    {currentStatus==='RECTIFICATION_SUBMITTED'&&<button className="secondary" onClick={()=>changeStatus('UNDER_REVIEW')}>Resume review</button>}
    {(currentStatus==='UNDER_REVIEW'||currentStatus==='RECTIFICATION_SUBMITTED')&&<button className="secondary warning-btn" onClick={()=>changeStatus('DEFICIENCY_RAISED')}>Raise deficiency</button>}
    {(currentStatus==='UNDER_REVIEW'||currentStatus==='RECTIFICATION_SUBMITTED')&&<button className="primary" onClick={()=>changeStatus('OFFICER_RECOMMENDATION_RECORDED')}>Record recommendation</button>}
    {currentStatus==='OFFICER_RECOMMENDATION_RECORDED'&&<button className="secondary" onClick={()=>changeStatus('CLOSED')}>Close workflow</button>}
    {(currentStatus==='UNDER_REVIEW'||currentStatus==='DEFICIENCY_RAISED')&&<button className="secondary" onClick={()=>changeStatus('CLOSED')}>Close workflow</button>}
  </>}
  </div></section>}

  {/* --- Officer Review Notes & Deficiency Form --- */}
  {isOfficerOrAdmin&&<section className="panel"><div className="panel-heading"><div><h2>Review observations & deficiency instructions</h2><p>Record observations, cite deficient findings, and specify correction instructions.</p></div></div>
  {isAssignedOfficer?<div style={{padding:'15px 20px'}}>
  <div style={{display:'flex',gap:'10px',marginBottom:'10px'}}>
  <select value={reviewAction} onChange={e=>setReviewAction(e.target.value)} style={{height:'39px',border:'1px solid #e0e5ef',borderRadius:'8px',padding:'0 12px',fontSize:'11px',background:'#fff'}}>
  <option value="REVIEW_NOTE">Review Note</option>
  <option value="DEFICIENCY_REQUEST">Deficiency Request</option>
  <option value="CORRECTION_ACCEPTED">Correction Accepted</option>
  <option value="RECOMMENDATION">Recommendation</option>
  </select>
  <button className="primary" onClick={submitReview} disabled={busy||!reviewNote.trim()}>Submit observation <ArrowUpRight size={15}/></button>
  </div>
  <textarea value={reviewNote} onChange={e=>setReviewNote(e.target.value)} placeholder="Enter your review observations and findings notes..." rows={3} style={{width:'100%',border:'1px solid #e0e5ef',borderRadius:'8px',padding:'10px 12px',fontSize:'11px',fontFamily:'inherit',resize:'vertical',marginBottom:'10px'}}/>
  {reviewAction==='DEFICIENCY_REQUEST'&&<div style={{display:'grid',gap:'8px',marginBottom:'10px'}}>
    <input value={findingRef} onChange={e=>setFindingRef(e.target.value)} placeholder="Referenced finding IDs (comma-separated, e.g. DOC-001, DOC-003)" style={{height:'37px',border:'1px solid #e0e5ef',borderRadius:'8px',padding:'0 12px',fontSize:'11px'}}/>
    <textarea value={correctionInstructions} onChange={e=>setCorrectionInstructions(e.target.value)} placeholder="Specific correction instructions for the institution (e.g. Upload notarized land lease agreement and revised faculty list)..." rows={2} style={{width:'100%',border:'1px solid #e0e5ef',borderRadius:'8px',padding:'8px 12px',fontSize:'11px',fontFamily:'inherit',resize:'vertical'}}/>
  </div>}
  </div>:<div style={{padding:'15px 20px',fontSize:'11px',color:'#8490a6'}}>Only the assigned compliance officer may record observations or deficiency requests.</div>}
  {/* Review history */}
  {detail?.reviews?.length>0&&<div className="doc-list">{detail.reviews.map(r=><div className="doc-row" key={r.id}><div className="doc-icon" style={{background:r.action==='DEFICIENCY_REQUEST'?'#fff0e8':r.action==='RECOMMENDATION'?'#eaf8f0':'#f0f2ff',color:r.action==='DEFICIENCY_REQUEST'?'#b55c2c':r.action==='RECOMMENDATION'?'#26845a':'#6573f4'}}><MessageSquare size={17}/></div><div className="doc-info"><strong>{r.action.replaceAll('_',' ')}</strong><small>{r.notes}</small>{r.correction_instructions&&<small style={{color:'#b55c2c',marginTop:'2px'}}><strong>Instructions: </strong>{r.correction_instructions}</small>}{r.finding_references?.length>0&&<small style={{color:'#6876ee',marginTop:'2px'}}><strong>Cited findings: </strong>{r.finding_references.join(', ')}</small>}<small style={{color:'#98a2b3',marginTop:'4px'}}>{r.created_at?new Date(r.created_at).toLocaleString():''} · Officer #{r.officer_id}</small></div></div>)}</div>}
  </section>}

  {/* --- Deficiency Memo --- */}
  {isOfficerOrAdmin&&<section className="panel"><div className="panel-heading"><div><h2>Deficiency memo assistant</h2><p>Optional Gemini-generated draft based only on current findings.</p></div>{isAssignedOfficer&&<button className="secondary" onClick={generateMemo}>Generate draft</button>}</div>{memo?<pre className="memo">{memo}</pre>:<div className="memo-placeholder">AI output is a draft only. Configure GEMINI_API_KEY on the backend to enable it; otherwise the app explains why it is unavailable.</div>}</section>}

  {/* Institution can view reviews/history read-only */}
  {isInstitution&&detail?.reviews?.length>0&&<section className="panel"><div className="panel-heading"><div><h2>Officer review history</h2><p>Review decisions and notes from compliance officers.</p></div><span className="count-pill">{detail.reviews.length} entries</span></div>
  <div className="doc-list">{detail.reviews.map(r=><div className="doc-row" key={r.id}><div className="doc-icon" style={{background:r.action==='DEFICIENCY_REQUEST'?'#fff0e8':r.action==='RECOMMENDATION'?'#eaf8f0':'#f0f2ff',color:r.action==='DEFICIENCY_REQUEST'?'#b55c2c':r.action==='RECOMMENDATION'?'#26845a':'#6573f4'}}><MessageSquare size={17}/></div><div className="doc-info"><strong>{r.action.replaceAll('_',' ')}</strong><small>{r.notes}</small>{r.correction_instructions&&<small style={{color:'#b55c2c',marginTop:'2px'}}><strong>Correction instructions: </strong>{r.correction_instructions}</small>}{r.finding_references?.length>0&&<small style={{color:'#6876ee',marginTop:'2px'}}><strong>Cited: </strong>{r.finding_references.join(', ')}</small>}<small style={{color:'#98a2b3',marginTop:'4px'}}>{r.created_at?new Date(r.created_at).toLocaleString():''}</small></div></div>)}</div>
  </section>}
  </>}
  </>}

  <div className="disclaimer"><ShieldCheck size={17}/><div><strong>Pre-screening only</strong><span>BroCode is a prototype decision-support tool. OCR, duplicate detection and AI-generated text are not proof of authenticity. No live AICTE API is connected; final regulatory decisions must be made by an authorized officer using applicable official sources.</span></div></div>
  <footer>© BroCode · SIH 26261 <span>Security-minded prototype · v1.2.0</span></footer>
  </div></main></div>
}

function Stat({icon,label,value,sub}){return <div className="stat"><div className="stat-top"><span>{label}</span><span className="stat-icon">{icon}</span></div><div className="stat-value">{value}</div><div className="stat-sub">{sub}</div></div>}

function Status({value}){let c=value==='CLOSED'?'closed':value==='DEFICIENCY_RAISED'?'deficiency':value==='UNDER_REVIEW'?'review':value==='RECTIFICATION_SUBMITTED'?'submitted':value==='OFFICER_RECOMMENDATION_RECORDED'?'review':'draft';return <span className={`status ${c}`}><i/>{(value||'DRAFT').replaceAll('_',' ')}</span>}

function Field({label,value}){return <div className="field"><span>{label}</span><strong>{value??'—'}</strong></div>}

createRoot(document.getElementById('root')).render(<App/>);
