#!/usr/bin/env python3
"""
BIP39 Dice TUI -- dice rolls to mnemonic, seed, root key, and addresses.

A terminal reimplementation of the core of Ian Coleman's BIP39 tool
(https://iancoleman.io/bip39/) with byte-for-byte compatible dice handling:

  * dice digits 1-6 are accepted; 6 is treated as 0 (base-6 events)
  * each event contributes bits: 0->00 1->01 2->10 3->11 4->0 5->1
  * "raw" length: the LAST multiple-of-32 bits become the entropy
  * fixed lengths (12/15/18/21/24): entropy = SHA-256 of the cleaned
    base-6 digit string, truncated to 32*words/3 bits
  * standard BIP39 checksum / wordlist lookup, BIP39 seed (PBKDF2),
    BIP32 root key, and BIP44/49/84/custom derivation with addresses

Pure Python 3 standard library. No network access, no dependencies.
Run it on an air-gapped machine for real keys.

Usage:
    python3 bip39_dice_tui.py                # interactive TUI
    python3 bip39_dice_tui.py --selftest     # run embedded test vectors
    python3 bip39_dice_tui.py --report --rolls 1234... [--length raw]
        [--passphrase X] [--tab bip84|bip49|bip44|bip32]
        [--path "m/84'/0'/0'"] [--addresses 10] [--show-private]
"""

import argparse
import curses
import hashlib
import hmac
import math
import struct
import sys
import unicodedata

WORDLIST = ['abandon','ability','able','about','above','absent','absorb','abstract','absurd','abuse','access','accident','account','accuse','achieve','acid','acoustic','acquire','across','act','action','actor','actress','actual','adapt','add','addict','address','adjust','admit','adult','advance','advice','aerobic','affair','afford','afraid','again','age','agent','agree','ahead','aim','air','airport','aisle','alarm','album','alcohol','alert','alien','all','alley','allow','almost','alone','alpha','already','also','alter','always','amateur','amazing','among','amount','amused','analyst','anchor','ancient','anger','angle','angry','animal','ankle','announce','annual','another','answer','antenna','antique','anxiety','any','apart','apology','appear','apple','approve','april','arch','arctic','area','arena','argue','arm','armed','armor','army','around','arrange','arrest','arrive','arrow','art','artefact','artist','artwork','ask','aspect','assault','asset','assist','assume','asthma','athlete','atom','attack','attend','attitude','attract','auction','audit','august','aunt','author','auto','autumn','average','avocado','avoid','awake','aware','away','awesome','awful','awkward','axis','baby','bachelor','bacon','badge','bag','balance','balcony','ball','bamboo','banana','banner','bar','barely','bargain','barrel','base','basic','basket','battle','beach','bean','beauty','because','become','beef','before','begin','behave','behind','believe','below','belt','bench','benefit','best','betray','better','between','beyond','bicycle','bid','bike','bind','biology','bird','birth','bitter','black','blade','blame','blanket','blast','bleak','bless','blind','blood','blossom','blouse','blue','blur','blush','board','boat','body','boil','bomb','bone','bonus','book','boost','border','boring','borrow','boss','bottom','bounce','box','boy','bracket','brain','brand','brass','brave','bread','breeze','brick','bridge','brief','bright','bring','brisk','broccoli','broken','bronze','broom','brother','brown','brush','bubble','buddy','budget','buffalo','build','bulb','bulk','bullet','bundle','bunker','burden','burger','burst','bus','business','busy','butter','buyer','buzz','cabbage','cabin','cable','cactus','cage','cake','call','calm','camera','camp','can','canal','cancel','candy','cannon','canoe','canvas','canyon','capable','capital','captain','car','carbon','card','cargo','carpet','carry','cart','case','cash','casino','castle','casual','cat','catalog','catch','category','cattle','caught','cause','caution','cave','ceiling','celery','cement','census','century','cereal','certain','chair','chalk','champion','change','chaos','chapter','charge','chase','chat','cheap','check','cheese','chef','cherry','chest','chicken','chief','child','chimney','choice','choose','chronic','chuckle','chunk','churn','cigar','cinnamon','circle','citizen','city','civil','claim','clap','clarify','claw','clay','clean','clerk','clever','click','client','cliff','climb','clinic','clip','clock','clog','close','cloth','cloud','clown','club','clump','cluster','clutch','coach','coast','coconut','code','coffee','coil','coin','collect','color','column','combine','come','comfort','comic','common','company','concert','conduct','confirm','congress','connect','consider','control','convince','cook','cool','copper','copy','coral','core','corn','correct','cost','cotton','couch','country','couple','course','cousin','cover','coyote','crack','cradle','craft','cram','crane','crash','crater','crawl','crazy','cream','credit','creek','crew','cricket','crime','crisp','critic','crop','cross','crouch','crowd','crucial','cruel','cruise','crumble','crunch','crush','cry','crystal','cube','culture','cup','cupboard','curious','current','curtain','curve','cushion','custom','cute','cycle','dad','damage','damp','dance','danger','daring','dash','daughter','dawn','day','deal','debate','debris','decade','december','decide','decline','decorate','decrease','deer','defense','define','defy','degree','delay','deliver','demand','demise','denial','dentist','deny','depart','depend','deposit','depth','deputy','derive','describe','desert','design','desk','despair','destroy','detail','detect','develop','device','devote','diagram','dial','diamond','diary','dice','diesel','diet','differ','digital','dignity','dilemma','dinner','dinosaur','direct','dirt','disagree','discover','disease','dish','dismiss','disorder','display','distance','divert','divide','divorce','dizzy','doctor','document','dog','doll','dolphin','domain','donate','donkey','donor','door','dose','double','dove','draft','dragon','drama','drastic','draw','dream','dress','drift','drill','drink','drip','drive','drop','drum','dry','duck','dumb','dune','during','dust','dutch','duty','dwarf','dynamic','eager','eagle','early','earn','earth','easily','east','easy','echo','ecology','economy','edge','edit','educate','effort','egg','eight','either','elbow','elder','electric','elegant','element','elephant','elevator','elite','else','embark','embody','embrace','emerge','emotion','employ','empower','empty','enable','enact','end','endless','endorse','enemy','energy','enforce','engage','engine','enhance','enjoy','enlist','enough','enrich','enroll','ensure','enter','entire','entry','envelope','episode','equal','equip','era','erase','erode','erosion','error','erupt','escape','essay','essence','estate','eternal','ethics','evidence','evil','evoke','evolve','exact','example','excess','exchange','excite','exclude','excuse','execute','exercise','exhaust','exhibit','exile','exist','exit','exotic','expand','expect','expire','explain','expose','express','extend','extra','eye','eyebrow','fabric','face','faculty','fade','faint','faith','fall','false','fame','family','famous','fan','fancy','fantasy','farm','fashion','fat','fatal','father','fatigue','fault','favorite','feature','february','federal','fee','feed','feel','female','fence','festival','fetch','fever','few','fiber','fiction','field','figure','file','film','filter','final','find','fine','finger','finish','fire','firm','first','fiscal','fish','fit','fitness','fix','flag','flame','flash','flat','flavor','flee','flight','flip','float','flock','floor','flower','fluid','flush','fly','foam','focus','fog','foil','fold','follow','food','foot','force','forest','forget','fork','fortune','forum','forward','fossil','foster','found','fox','fragile','frame','frequent','fresh','friend','fringe','frog','front','frost','frown','frozen','fruit','fuel','fun','funny','furnace','fury','future','gadget','gain','galaxy','gallery','game','gap','garage','garbage','garden','garlic','garment','gas','gasp','gate','gather','gauge','gaze','general','genius','genre','gentle','genuine','gesture','ghost','giant','gift','giggle','ginger','giraffe','girl','give','glad','glance','glare','glass','glide','glimpse','globe','gloom','glory','glove','glow','glue','goat','goddess','gold','good','goose','gorilla','gospel','gossip','govern','gown','grab','grace','grain','grant','grape','grass','gravity','great','green','grid','grief','grit','grocery','group','grow','grunt','guard','guess','guide','guilt','guitar','gun','gym','habit','hair','half','hammer','hamster','hand','happy','harbor','hard','harsh','harvest','hat','have','hawk','hazard','head','health','heart','heavy','hedgehog','height','hello','helmet','help','hen','hero','hidden','high','hill','hint','hip','hire','history','hobby','hockey','hold','hole','holiday','hollow','home','honey','hood','hope','horn','horror','horse','hospital','host','hotel','hour','hover','hub','huge','human','humble','humor','hundred','hungry','hunt','hurdle','hurry','hurt','husband','hybrid','ice','icon','idea','identify','idle','ignore','ill','illegal','illness','image','imitate','immense','immune','impact','impose','improve','impulse','inch','include','income','increase','index','indicate','indoor','industry','infant','inflict','inform','inhale','inherit','initial','inject','injury','inmate','inner','innocent','input','inquiry','insane','insect','inside','inspire','install','intact','interest','into','invest','invite','involve','iron','island','isolate','issue','item','ivory','jacket','jaguar','jar','jazz','jealous','jeans','jelly','jewel','job','join','joke','journey','joy','judge','juice','jump','jungle','junior','junk','just','kangaroo','keen','keep','ketchup','key','kick','kid','kidney','kind','kingdom','kiss','kit','kitchen','kite','kitten','kiwi','knee','knife','knock','know','lab','label','labor','ladder','lady','lake','lamp','language','laptop','large','later','latin','laugh','laundry','lava','law','lawn','lawsuit','layer','lazy','leader','leaf','learn','leave','lecture','left','leg','legal','legend','leisure','lemon','lend','length','lens','leopard','lesson','letter','level','liar','liberty','library','license','life','lift','light','like','limb','limit','link','lion','liquid','list','little','live','lizard','load','loan','lobster','local','lock','logic','lonely','long','loop','lottery','loud','lounge','love','loyal','lucky','luggage','lumber','lunar','lunch','luxury','lyrics','machine','mad','magic','magnet','maid','mail','main','major','make','mammal','man','manage','mandate','mango','mansion','manual','maple','marble','march','margin','marine','market','marriage','mask','mass','master','match','material','math','matrix','matter','maximum','maze','meadow','mean','measure','meat','mechanic','medal','media','melody','melt','member','memory','mention','menu','mercy','merge','merit','merry','mesh','message','metal','method','middle','midnight','milk','million','mimic','mind','minimum','minor','minute','miracle','mirror','misery','miss','mistake','mix','mixed','mixture','mobile','model','modify','mom','moment','monitor','monkey','monster','month','moon','moral','more','morning','mosquito','mother','motion','motor','mountain','mouse','move','movie','much','muffin','mule','multiply','muscle','museum','mushroom','music','must','mutual','myself','mystery','myth','naive','name','napkin','narrow','nasty','nation','nature','near','neck','need','negative','neglect','neither','nephew','nerve','nest','net','network','neutral','never','news','next','nice','night','noble','noise','nominee','noodle','normal','north','nose','notable','note','nothing','notice','novel','now','nuclear','number','nurse','nut','oak','obey','object','oblige','obscure','observe','obtain','obvious','occur','ocean','october','odor','off','offer','office','often','oil','okay','old','olive','olympic','omit','once','one','onion','online','only','open','opera','opinion','oppose','option','orange','orbit','orchard','order','ordinary','organ','orient','original','orphan','ostrich','other','outdoor','outer','output','outside','oval','oven','over','own','owner','oxygen','oyster','ozone','pact','paddle','page','pair','palace','palm','panda','panel','panic','panther','paper','parade','parent','park','parrot','party','pass','patch','path','patient','patrol','pattern','pause','pave','payment','peace','peanut','pear','peasant','pelican','pen','penalty','pencil','people','pepper','perfect','permit','person','pet','phone','photo','phrase','physical','piano','picnic','picture','piece','pig','pigeon','pill','pilot','pink','pioneer','pipe','pistol','pitch','pizza','place','planet','plastic','plate','play','please','pledge','pluck','plug','plunge','poem','poet','point','polar','pole','police','pond','pony','pool','popular','portion','position','possible','post','potato','pottery','poverty','powder','power','practice','praise','predict','prefer','prepare','present','pretty','prevent','price','pride','primary','print','priority','prison','private','prize','problem','process','produce','profit','program','project','promote','proof','property','prosper','protect','proud','provide','public','pudding','pull','pulp','pulse','pumpkin','punch','pupil','puppy','purchase','purity','purpose','purse','push','put','puzzle','pyramid','quality','quantum','quarter','question','quick','quit','quiz','quote','rabbit','raccoon','race','rack','radar','radio','rail','rain','raise','rally','ramp','ranch','random','range','rapid','rare','rate','rather','raven','raw','razor','ready','real','reason','rebel','rebuild','recall','receive','recipe','record','recycle','reduce','reflect','reform','refuse','region','regret','regular','reject','relax','release','relief','rely','remain','remember','remind','remove','render','renew','rent','reopen','repair','repeat','replace','report','require','rescue','resemble','resist','resource','response','result','retire','retreat','return','reunion','reveal','review','reward','rhythm','rib','ribbon','rice','rich','ride','ridge','rifle','right','rigid','ring','riot','ripple','risk','ritual','rival','river','road','roast','robot','robust','rocket','romance','roof','rookie','room','rose','rotate','rough','round','route','royal','rubber','rude','rug','rule','run','runway','rural','sad','saddle','sadness','safe','sail','salad','salmon','salon','salt','salute','same','sample','sand','satisfy','satoshi','sauce','sausage','save','say','scale','scan','scare','scatter','scene','scheme','school','science','scissors','scorpion','scout','scrap','screen','script','scrub','sea','search','season','seat','second','secret','section','security','seed','seek','segment','select','sell','seminar','senior','sense','sentence','series','service','session','settle','setup','seven','shadow','shaft','shallow','share','shed','shell','sheriff','shield','shift','shine','ship','shiver','shock','shoe','shoot','shop','short','shoulder','shove','shrimp','shrug','shuffle','shy','sibling','sick','side','siege','sight','sign','silent','silk','silly','silver','similar','simple','since','sing','siren','sister','situate','six','size','skate','sketch','ski','skill','skin','skirt','skull','slab','slam','sleep','slender','slice','slide','slight','slim','slogan','slot','slow','slush','small','smart','smile','smoke','smooth','snack','snake','snap','sniff','snow','soap','soccer','social','sock','soda','soft','solar','soldier','solid','solution','solve','someone','song','soon','sorry','sort','soul','sound','soup','source','south','space','spare','spatial','spawn','speak','special','speed','spell','spend','sphere','spice','spider','spike','spin','spirit','split','spoil','sponsor','spoon','sport','spot','spray','spread','spring','spy','square','squeeze','squirrel','stable','stadium','staff','stage','stairs','stamp','stand','start','state','stay','steak','steel','stem','step','stereo','stick','still','sting','stock','stomach','stone','stool','story','stove','strategy','street','strike','strong','struggle','student','stuff','stumble','style','subject','submit','subway','success','such','sudden','suffer','sugar','suggest','suit','summer','sun','sunny','sunset','super','supply','supreme','sure','surface','surge','surprise','surround','survey','suspect','sustain','swallow','swamp','swap','swarm','swear','sweet','swift','swim','swing','switch','sword','symbol','symptom','syrup','system','table','tackle','tag','tail','talent','talk','tank','tape','target','task','taste','tattoo','taxi','teach','team','tell','ten','tenant','tennis','tent','term','test','text','thank','that','theme','then','theory','there','they','thing','this','thought','three','thrive','throw','thumb','thunder','ticket','tide','tiger','tilt','timber','time','tiny','tip','tired','tissue','title','toast','tobacco','today','toddler','toe','together','toilet','token','tomato','tomorrow','tone','tongue','tonight','tool','tooth','top','topic','topple','torch','tornado','tortoise','toss','total','tourist','toward','tower','town','toy','track','trade','traffic','tragic','train','transfer','trap','trash','travel','tray','treat','tree','trend','trial','tribe','trick','trigger','trim','trip','trophy','trouble','truck','true','truly','trumpet','trust','truth','try','tube','tuition','tumble','tuna','tunnel','turkey','turn','turtle','twelve','twenty','twice','twin','twist','two','type','typical','ugly','umbrella','unable','unaware','uncle','uncover','under','undo','unfair','unfold','unhappy','uniform','unique','unit','universe','unknown','unlock','until','unusual','unveil','update','upgrade','uphold','upon','upper','upset','urban','urge','usage','use','used','useful','useless','usual','utility','vacant','vacuum','vague','valid','valley','valve','van','vanish','vapor','various','vast','vault','vehicle','velvet','vendor','venture','venue','verb','verify','version','very','vessel','veteran','viable','vibrant','vicious','victory','video','view','village','vintage','violin','virtual','virus','visa','visit','visual','vital','vivid','vocal','voice','void','volcano','volume','vote','voyage','wage','wagon','wait','walk','wall','walnut','want','warfare','warm','warrior','wash','wasp','waste','water','wave','way','wealth','weapon','wear','weasel','weather','web','wedding','weekend','weird','welcome','west','wet','whale','what','wheat','wheel','when','where','whip','whisper','wide','width','wife','wild','will','win','window','wine','wing','wink','winner','winter','wire','wisdom','wise','wish','witness','wolf','woman','wonder','wood','wool','word','work','world','worry','worth','wrap','wreck','wrestle','wrist','write','wrong','yard','year','yellow','you','young','youth','zebra','zero','zone','zoo']

# ======================================================================
# RIPEMD-160 (pure-Python fallback; OpenSSL 3 often ships without it)
# ======================================================================

def _has_native_ripemd():
    try:
        hashlib.new("ripemd160", b"")
        return True
    except Exception:
        return False

_NATIVE_RIPEMD = _has_native_ripemd()

_RMD_R = [
    [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
    [7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8],
    [3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12],
    [1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2],
    [4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13],
]
_RMD_RR = [
    [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12],
    [6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2],
    [15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13],
    [8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14],
    [12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11],
]
_RMD_S = [
    [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8],
    [7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12],
    [11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5],
    [11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12],
    [9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6],
]
_RMD_SS = [
    [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6],
    [9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11],
    [9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5],
    [15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8],
    [8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11],
]
_RMD_K = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
_RMD_KK = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]
_M32 = 0xFFFFFFFF

def _rol(x, n):
    return ((x << n) | (x >> (32 - n))) & _M32

def _rmd_f(j, x, y, z):
    if j == 0:
        return x ^ y ^ z
    if j == 1:
        return (x & y) | (~x & z)
    if j == 2:
        return (x | ~y) ^ z
    if j == 3:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)

def _ripemd160_pure(data: bytes) -> bytes:
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    # MD-style padding, little-endian bit length
    msg = data + b"\x80"
    while len(msg) % 64 != 56:
        msg += b"\x00"
    msg += struct.pack("<Q", len(data) * 8)
    for off in range(0, len(msg), 64):
        x = struct.unpack("<16I", msg[off:off + 64])
        a, b, c, d, e = h
        aa, bb, cc, dd, ee = h
        for rnd in range(5):
            for i in range(16):
                # left line
                t = (a + _rmd_f(rnd, b, c, d) + x[_RMD_R[rnd][i]]
                     + _RMD_K[rnd]) & _M32
                t = (_rol(t, _RMD_S[rnd][i]) + e) & _M32
                a, e, d, c, b = e, d, _rol(c, 10), b, t
                # right line
                tt = (aa + _rmd_f(4 - rnd, bb, cc, dd) + x[_RMD_RR[rnd][i]]
                      + _RMD_KK[rnd]) & _M32
                tt = (_rol(tt, _RMD_SS[rnd][i]) + ee) & _M32
                aa, ee, dd, cc, bb = ee, dd, _rol(cc, 10), bb, tt
        t = (h[1] + c + dd) & _M32
        h[1] = (h[2] + d + ee) & _M32
        h[2] = (h[3] + e + aa) & _M32
        h[3] = (h[4] + a + bb) & _M32
        h[4] = (h[0] + b + cc) & _M32
        h[0] = t
    return struct.pack("<5I", *h)

def ripemd160(data: bytes) -> bytes:
    if _NATIVE_RIPEMD:
        return hashlib.new("ripemd160", data).digest()
    return _ripemd160_pure(data)

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def hash160(data: bytes) -> bytes:
    return ripemd160(sha256(data))

# ======================================================================
# Base58Check
# ======================================================================

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58encode(data: bytes) -> str:
    num = int.from_bytes(data, "big")
    out = []
    while num > 0:
        num, rem = divmod(num, 58)
        out.append(_B58[rem])
    for byte in data:
        if byte == 0:
            out.append(_B58[0])
        else:
            break
    return "".join(reversed(out))

def b58check(payload: bytes) -> str:
    return b58encode(payload + sha256(sha256(payload))[:4])

# ======================================================================
# Bech32 (BIP173) for native segwit addresses
# ======================================================================

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def _bech32_polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk

def _bech32_hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]

def _bech32_encode(hrp, data):
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in data + checksum)

def _convertbits(data, frombits, tobits, pad=True):
    acc, bits, ret = 0, 0, []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret

def segwit_v0_address(witness_program: bytes, hrp: str = "bc") -> str:
    return _bech32_encode(hrp, [0] + _convertbits(witness_program, 8, 5))

# ======================================================================
# secp256k1
# ======================================================================

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def _pt_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % _P == 0:
        return None
    if p == q:
        lam = (3 * p[0] * p[0]) * pow(2 * p[1], _P - 2, _P) % _P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], _P - 2, _P) % _P
    x = (lam * lam - p[0] - q[0]) % _P
    y = (lam * (p[0] - x) - p[1]) % _P
    return (x, y)

# Jacobian coordinates (X, Y, Z) with affine x = X/Z^2, y = Y/Z^3.
# Avoids a modular inversion per point operation; one inversion at the end.

def _jac_double(pt):
    if pt is None or pt[1] == 0:
        return None
    x, y, z = pt
    s = (4 * x * y * y) % _P
    m = (3 * x * x) % _P                     # a = 0 for secp256k1
    nx = (m * m - 2 * s) % _P
    ny = (m * (s - nx) - 8 * pow(y, 4, _P)) % _P
    nz = (2 * y * z) % _P
    return (nx, ny, nz)

def _jac_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1, z1 = p
    x2, y2, z2 = q
    z1s, z2s = (z1 * z1) % _P, (z2 * z2) % _P
    u1, u2 = (x1 * z2s) % _P, (x2 * z1s) % _P
    s1, s2 = (y1 * z2s * z2) % _P, (y2 * z1s * z1) % _P
    if u1 == u2:
        if s1 != s2:
            return None
        return _jac_double(p)
    h = (u2 - u1) % _P
    r = (s2 - s1) % _P
    h2 = (h * h) % _P
    h3 = (h2 * h) % _P
    u1h2 = (u1 * h2) % _P
    nx = (r * r - h3 - 2 * u1h2) % _P
    ny = (r * (u1h2 - nx) - s1 * h3) % _P
    nz = (h * z1 * z2) % _P
    return (nx, ny, nz)

def _pt_mul(k, point=_G):
    result = None
    addend = (point[0], point[1], 1)
    while k:
        if k & 1:
            result = _jac_add(result, addend)
        addend = _jac_double(addend)
        k >>= 1
    if result is None:
        return None
    x, y, z = result
    zinv = pow(z, _P - 2, _P)
    zinv2 = (zinv * zinv) % _P
    return ((x * zinv2) % _P, (y * zinv2 * zinv) % _P)

def priv_to_pub(priv: bytes) -> bytes:
    """Compressed SEC1 public key for a 32-byte private key."""
    point = _pt_mul(int.from_bytes(priv, "big"))
    prefix = b"\x02" if point[1] % 2 == 0 else b"\x03"
    return prefix + point[0].to_bytes(32, "big")

def _pub_decompress(pub: bytes):
    x = int.from_bytes(pub[1:], "big")
    y_sq = (pow(x, 3, _P) + 7) % _P
    y = pow(y_sq, (_P + 1) // 4, _P)
    if (y % 2 == 0) != (pub[0] == 0x02):
        y = _P - y
    return (x, y)

# ======================================================================
# Dice fairness statistics (chi-squared goodness of fit, df = 5)
# ======================================================================

def _gammp(a: float, x: float) -> float:
    """Regularized lower incomplete gamma P(a, x); ~1e-14 accuracy."""
    if x <= 0.0:
        return 0.0
    if x < a + 1.0:  # series representation
        ap, total, term = a, 1.0 / a, 1.0 / a
        for _ in range(500):
            ap += 1.0
            term *= x / ap
            total += term
            if abs(term) < abs(total) * 1e-15:
                break
        return total * math.exp(-x + a * math.log(x) - math.lgamma(a))
    # continued fraction for Q(a, x), then P = 1 - Q
    tiny = 1e-300
    b = x + 1.0 - a
    c = 1.0 / tiny
    d = 1.0 / b
    h = d
    for i in range(1, 500):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-15:
            break
    q = math.exp(-x + a * math.log(x) - math.lgamma(a)) * h
    return 1.0 - q

def chi2_pvalue(stat: float, df: int = 5) -> float:
    """P(chi2 >= stat) for the given degrees of freedom."""
    p = 1.0 - _gammp(df / 2.0, stat / 2.0)
    return min(1.0, max(0.0, p))

def fairness_stats(rolls: str):
    """Face-frequency fairness stats on the raw rolls (faces 1-6).

    Returns None when there are no rolls. Uses the same math as the
    standalone dice analyzer (chi-squared df=5 + entropy estimates).
    """
    counts = {f: 0 for f in "123456"}
    for c in rolls:
        if c in counts:
            counts[c] += 1
    n = sum(counts.values())
    if n == 0:
        return None
    exp = n / 6.0
    chi2 = sum((counts[f] - exp) ** 2 / exp for f in counts)
    p = chi2_pvalue(chi2)
    probs = [counts[f] / n for f in "123456"]
    shannon = -sum(q * math.log2(q) for q in probs if q > 0)
    min_ent = -math.log2(max(probs))
    hi = max("123456", key=lambda f: counts[f])
    lo = min("123456", key=lambda f: counts[f])
    return {
        "n": n, "counts": counts, "expected": exp,
        "chi2": chi2, "p": p,
        "shannon": shannon, "min_ent": min_ent,
        "total_min_ent": min_ent * n,
        "hi": hi, "hi_dev": (counts[hi] - exp) / exp * 100 if exp else 0.0,
        "lo": lo, "lo_dev": (counts[lo] - exp) / exp * 100 if exp else 0.0,
    }

def fairness_verdict(stats) -> str:
    if stats["n"] < 30:
        return ("too few rolls for a meaningful test "
                "(~100+ recommended)")
    if stats["p"] >= 0.05:
        return "no evidence of bias (normal range for fair dice)"
    if stats["p"] >= 0.01:
        return "borderline -- possibly unlucky, possibly biased; roll more"
    return "SUSPICIOUS -- distribution unlikely for fair dice (p < 0.01)"

# ======================================================================
# BIP39
# ======================================================================

_DICE_BITS = {"0": "00", "1": "01", "2": "10", "3": "11", "4": "0", "5": "1"}

def dice_to_events(raw: str) -> str:
    """Filter to 1-6 and convert to base-6 events (6 -> 0). Coleman-exact."""
    return "".join("0" if c == "6" else c for c in raw if c in "123456")

def events_to_bits(events: str) -> str:
    return "".join(_DICE_BITS[c] for c in events)

def entropy_binary(events: str, length) -> str:
    """Return the final entropy bit string per Coleman's setMnemonicFromEntropy.

    length is 'raw' or an int in {12, 15, 18, 21, 24}.
    """
    bits = events_to_bits(events)
    if length != "raw":
        digest = sha256(events.encode("ascii"))
        bits = bin(int.from_bytes(digest, "big"))[2:].zfill(256)
        bits = bits[: 32 * int(length) // 3]
    use = (len(bits) // 32) * 32
    return bits[len(bits) - use:]

def binstr_to_mnemonic(binstr: str):
    """Standard BIP39: entropy bits -> (indexes, words, checksum_bits)."""
    ent = bytes(int(binstr[i:i + 8], 2) for i in range(0, len(binstr), 8))
    cs_len = len(binstr) // 32
    cs = bin(int.from_bytes(sha256(ent), "big"))[2:].zfill(256)[:cs_len]
    full = binstr + cs
    idxs = [int(full[i:i + 11], 2) for i in range(0, len(full), 11)]
    return idxs, [WORDLIST[i] for i in idxs], cs

def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    mnemonic = unicodedata.normalize("NFKD", mnemonic)
    salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase)
    return hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), salt.encode(), 2048)

# ======================================================================
# BIP32
# ======================================================================

VERSIONS = {  # (private, public) serialization version bytes
    "x": (0x0488ADE4, 0x0488B21E),   # BIP44 / BIP32  xprv/xpub
    "y": (0x049D7878, 0x049D7CB2),   # BIP49          yprv/ypub
    "z": (0x04B2430C, 0x04B24746),   # BIP84          zprv/zpub
}

HARDENED = 0x80000000

class HDKey:
    __slots__ = ("key", "chain", "depth", "parent_fp", "child")

    def __init__(self, key, chain, depth=0, parent_fp=b"\x00" * 4, child=0):
        self.key = key            # 32-byte private key
        self.chain = chain        # 32-byte chain code
        self.depth = depth
        self.parent_fp = parent_fp
        self.child = child

    @classmethod
    def from_seed(cls, seed: bytes):
        i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        return cls(i[:32], i[32:])

    @property
    def pub(self) -> bytes:
        return priv_to_pub(self.key)

    @property
    def fingerprint(self) -> bytes:
        return hash160(self.pub)[:4]

    def ckd_priv(self, index: int):
        if index >= HARDENED:
            data = b"\x00" + self.key + struct.pack(">I", index)
        else:
            data = self.pub + struct.pack(">I", index)
        i = hmac.new(self.chain, data, hashlib.sha512).digest()
        il = int.from_bytes(i[:32], "big")
        child_key = (il + int.from_bytes(self.key, "big")) % _N
        if il >= _N or child_key == 0:  # ~2^-127; skip per BIP32
            return self.ckd_priv(index + 1)
        return HDKey(child_key.to_bytes(32, "big"), i[32:],
                     self.depth + 1, self.fingerprint, index)

    def _serialize(self, version: int, key33: bytes) -> str:
        payload = (struct.pack(">I", version) + bytes([self.depth])
                   + self.parent_fp + struct.pack(">I", self.child)
                   + self.chain + key33)
        return b58check(payload)

    def xprv(self, scheme="x") -> str:
        return self._serialize(VERSIONS[scheme][0], b"\x00" + self.key)

    def xpub(self, scheme="x") -> str:
        return self._serialize(VERSIONS[scheme][1], self.pub)

    def wif(self) -> str:
        return b58check(b"\x80" + self.key + b"\x01")  # compressed

def parse_path(path: str):
    """'m/84'/0'/0'' -> list of child indexes. Accepts ', h, H."""
    path = path.strip()
    if path in ("m", "M", ""):
        return []
    parts = path.split("/")
    if parts[0] in ("m", "M"):
        parts = parts[1:]
    out = []
    for part in parts:
        if not part:
            raise ValueError("empty path segment")
        hardened = part[-1] in "'hH"
        if hardened:
            part = part[:-1]
        if not part.isdigit():
            raise ValueError(f"bad path segment: {part!r}")
        idx = int(part)
        if idx >= HARDENED:
            raise ValueError(f"index too large: {idx}")
        out.append(idx + HARDENED if hardened else idx)
    return out

def derive_path(root: HDKey, path: str) -> HDKey:
    node = root
    for idx in parse_path(path):
        node = node.ckd_priv(idx)
    return node

# ======================================================================
# Addresses
# ======================================================================

def addr_p2pkh(pub: bytes) -> str:
    return b58check(b"\x00" + hash160(pub))

def addr_p2sh_p2wpkh(pub: bytes) -> str:
    redeem = b"\x00\x14" + hash160(pub)
    return b58check(b"\x05" + hash160(redeem))

def addr_p2wpkh(pub: bytes) -> str:
    return segwit_v0_address(hash160(pub))

TABS = {
    "bip44": {"purpose": "44'", "scheme": "x", "addr": addr_p2pkh,
              "label": "BIP44 (legacy, 1...)"},
    "bip49": {"purpose": "49'", "scheme": "y", "addr": addr_p2sh_p2wpkh,
              "label": "BIP49 (segwit-compat, 3...)"},
    "bip84": {"purpose": "84'", "scheme": "z", "addr": addr_p2wpkh,
              "label": "BIP84 (native segwit, bc1...)"},
    "bip32": {"purpose": None, "scheme": "x", "addr": addr_p2pkh,
              "label": "BIP32 (custom path, legacy addresses)"},
}
TAB_ORDER = ["bip84", "bip49", "bip44", "bip32"]

# ======================================================================
# Model: compute everything from inputs
# ======================================================================

LENGTHS = ["raw", 12, 15, 18, 21, 24]

def default_path(tab: str) -> str:
    if tab == "bip32":
        return "m/0"
    return f"m/{TABS[tab]['purpose']}/0'/0'"

def compute(rolls: str, length, passphrase: str, tab: str,
            custom_path: str, n_addresses: int):
    """Return a dict with every derived field, or partial dict + error."""
    out = {"error": None}
    events = dice_to_events(rolls)
    bits = events_to_bits(events)
    out["events"] = events
    out["event_count"] = len(events)
    out["ignored"] = len("".join(rolls.split())) - sum(
        1 for c in rolls if c in "123456")
    out["bits"] = bits
    out["bit_count"] = len(bits)
    out["fairness"] = fairness_stats(rolls)

    binstr = entropy_binary(events, length)
    out["entropy_bits_used"] = binstr
    if not binstr:
        out["error"] = ("need more rolls: at least 32 bits of entropy "
                        "(about 13 rolls) before any words appear")
        return out
    if length != "raw" and len(binstr) != 32 * int(length) // 3:
        out["error"] = "internal: unexpected entropy width"
        return out

    idxs, words, cs = binstr_to_mnemonic(binstr)
    out["entropy_hex"] = "%0*x" % (len(binstr) // 4, int(binstr, 2))
    out["word_indexes"] = idxs
    out["words"] = words
    out["checksum"] = cs
    mnemonic = " ".join(words)
    out["mnemonic"] = mnemonic

    seed = mnemonic_to_seed(mnemonic, passphrase)
    out["seed_hex"] = seed.hex()

    root = HDKey.from_seed(seed)
    out["root_xprv"] = root.xprv("x")

    tabinfo = TABS[tab]
    path = custom_path if tab == "bip32" else default_path(tab)
    out["tab"] = tab
    out["tab_label"] = tabinfo["label"]
    out["account_path"] = path
    try:
        account = derive_path(root, path)
    except ValueError as exc:
        out["error"] = f"bad derivation path: {exc}"
        return out
    scheme = tabinfo["scheme"]
    out["account_xprv"] = account.xprv(scheme)
    out["account_xpub"] = account.xpub(scheme)

    # Address chain: BIP44/49/84 derive account/0/i (external chain);
    # custom BIP32 derives path/i, matching Coleman's BIP32 tab.
    rows = []
    if tab == "bip32":
        chain_node, chain_path = account, path
    else:
        chain_node, chain_path = account.ckd_priv(0), path + "/0"
    for i in range(n_addresses):
        node = chain_node.ckd_priv(i)
        pub = node.pub
        rows.append({
            "path": f"{chain_path}/{i}",
            "address": tabinfo["addr"](pub),
            "pub": pub.hex(),
            "wif": node.wif(),
        })
    out["addresses"] = rows
    return out

# ======================================================================
# Report mode (plain text; also used by tests)
# ======================================================================

def wrap(s, width, indent="    "):
    return [indent + s[i:i + width] for i in range(0, len(s), width)] or [indent]

def report_lines(state, width=76, show_private=False):
    L = []
    add = L.append
    err = state.get("error")
    add("ENTROPY")
    add(f"    events (base 6, dice 6->0): {state['event_count']}"
        + (f"   [{state['ignored']} non-dice chars ignored]"
           if state.get("ignored") else ""))
    if state["events"]:
        L += wrap(state["events"], width - 4)
    add(f"    total bits collected: {state['bit_count']}"
        f"   (~2.585 max per roll; this encoding averages ~2.58)")
    add("    raw binary:")
    L += wrap(state["bits"] or "(none)", width - 4)
    if not err:
        add(f"    entropy used ({len(state['entropy_bits_used'])} bits, "
            f"hex): {state['entropy_hex']}")
    fs = state.get("fairness")
    if fs:
        add("")
        add("FAIRNESS (chi-squared goodness of fit, df = 5)")
        bar_max = max(fs["counts"].values()) or 1
        bar_w = max(10, min(30, width - 40))
        for f in "123456":
            cnt = fs["counts"][f]
            pct = 100.0 * cnt / fs["n"]
            dev = (cnt - fs["expected"]) / fs["expected"] * 100
            bar = "#" * max(1 if cnt else 0,
                            round(bar_w * cnt / bar_max))
            add(f"    {f} | {cnt:4d}  {pct:5.1f}%  {dev:+6.1f}%  {bar}")
        add(f"    rolls: {fs['n']}   expected/face: {fs['expected']:.1f}"
            f"   chi2: {fs['chi2']:.3f}   p-value: {fs['p']:.4f}")
        add(f"    over: face {fs['hi']} ({fs['hi_dev']:+.1f}%)"
            f"   under: face {fs['lo']} ({fs['lo_dev']:+.1f}%)")
        add(f"    verdict: {fairness_verdict(fs)}")
        add(f"    entropy/roll: Shannon {fs['shannon']:.4f}, "
            f"min-entropy {fs['min_ent']:.4f} (fair max 2.5850)")
        add(f"    total min-entropy: ~{fs['total_min_ent']:.0f} bits"
            f"   (>= 256 for a full-strength 24-word seed: "
            f"{'YES' if fs['total_min_ent'] >= 256 else 'not yet'})")
    if err:
        add("")
        add(f"!!  {err}")
        return L
    add("")
    add("MNEMONIC")
    add(f"    length: {len(state['words'])} words"
        f"   checksum bits: {state['checksum']}")
    add("    word indexes:")
    L += wrap(", ".join(str(i) for i in state["word_indexes"]), width - 4)
    add("    BIP39 mnemonic:")
    numbered = [f"{i+1}.{w}" for i, w in enumerate(state["words"])]
    line = ""
    for token in numbered:
        if len(line) + len(token) + 1 > width - 4:
            add("    " + line)
            line = token
        else:
            line = token if not line else line + " " + token
    if line:
        add("    " + line)
    add("")
    add("SEED / KEYS")
    add("    BIP39 seed:")
    L += wrap(state["seed_hex"], width - 4)
    add("    BIP32 root key:")
    L += wrap(state["root_xprv"], width - 4)
    add("")
    add(f"DERIVATION -- {state['tab_label']}")
    add(f"    path: {state['account_path']}")
    add("    account xprv:")
    L += wrap(state["account_xprv"], width - 4)
    add("    account xpub:")
    L += wrap(state["account_xpub"], width - 4)
    add("")
    add("ADDRESSES")
    for row in state["addresses"]:
        add(f"    {row['path']}")
        add(f"        addr {row['address']}")
        add(f"        pub  {row['pub']}")
        add(f"        wif  {row['wif'] if show_private else '(hidden)'}")
    return L

# ======================================================================
# Self-test: official BIP39 / BIP32 / address vectors
# ======================================================================

def selftest():
    ok = True

    def check(name, got, want):
        nonlocal ok
        if got != want:
            ok = False
            print(f"FAIL {name}\n  got  {got}\n  want {want}")
        else:
            print(f"ok   {name}")

    # RIPEMD-160 (pure implementation, regardless of native availability)
    check("ripemd160(empty)", _ripemd160_pure(b"").hex(),
          "9c1185a5c5e9fc54612808977ee8f548b2258d31")
    check("ripemd160(abc)", _ripemd160_pure(b"abc").hex(),
          "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")

    # BIP39 official vector #1 (passphrase TREZOR)
    idxs, words, _ = binstr_to_mnemonic("0" * 128)
    check("bip39 vec1 mnemonic", " ".join(words),
          "abandon abandon abandon abandon abandon abandon abandon abandon "
          "abandon abandon abandon about")
    seed = mnemonic_to_seed(" ".join(words), "TREZOR")
    check("bip39 vec1 seed", seed.hex(),
          "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
          "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")
    check("bip39 vec1 root", HDKey.from_seed(seed).xprv(),
          "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23w"
          "pbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF")

    # BIP32 test vector 1
    root = HDKey.from_seed(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    check("bip32 vec1 m xprv", root.xprv(),
          "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkV"
          "vvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
    check("bip32 vec1 m xpub", root.xpub(),
          "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29"
          "ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
    m0h = derive_path(root, "m/0'")
    check("bip32 vec1 m/0' xprv", m0h.xprv(),
          "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1r"
          "GL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7")
    chain = derive_path(root, "m/0'/1/2'/2/1000000000")
    check("bip32 vec1 deep xprv", chain.xprv(),
          "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHS"
          "cGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76")

    # Address forms from the canonical demo key (priv = 1)
    pub = priv_to_pub((1).to_bytes(32, "big"))
    check("p2pkh(priv=1)", addr_p2pkh(pub),
          "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
    check("bech32(priv=1)", addr_p2wpkh(pub),
          "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    check("wif(priv=1)", b58check(b"\x80" + (1).to_bytes(32, "big") + b"\x01"),
          "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")
    check("pub decompress roundtrip",
          _pub_decompress(pub)[0], _G[0])

    # Chi-squared p-value (verified against scipy to ~1e-15 in development;
    # 7.890 / p=0.1624 is the reference case from real 182-roll data)
    check("chi2 p(7.890, df=5)", round(chi2_pvalue(7.890), 4), 0.1624)
    check("chi2 p(0) == 1", chi2_pvalue(0.0), 1.0)
    check("chi2 p large stat ~ 0", chi2_pvalue(500.0) < 1e-90, True)

    print("\nALL TESTS PASSED" if ok else "\nSOME TESTS FAILED")
    return ok

# ======================================================================
# TUI
# ======================================================================

FIELD_ROLLS, FIELD_LENGTH, FIELD_PASS, FIELD_TAB, FIELD_PATH = range(5)

class Tui:
    def __init__(self):
        self.rolls = ""
        self.length_i = 0                 # index into LENGTHS
        self.passphrase = ""
        self.tab_i = 0                    # index into TAB_ORDER
        self.custom_path = "m/0"
        self.n_addresses = 10
        self.show_private = False
        self.focus = FIELD_ROLLS
        self.cursor = 0                   # cursor within focused text field
        self.scroll = 0
        self._cache_key = None
        self._cache_val = None

    # ---- state helpers ----
    @property
    def length(self):
        return LENGTHS[self.length_i]

    @property
    def tab(self):
        return TAB_ORDER[self.tab_i]

    def state(self):
        key = self._inputs_key()
        if key != self._cache_key:
            self._cache_val = compute(*key)
            self._cache_key = key
        return self._cache_val

    def field_text(self, field):
        if field == FIELD_ROLLS:
            return self.rolls
        if field == FIELD_PASS:
            return self.passphrase
        if field == FIELD_PATH:
            return self.custom_path
        return ""

    def set_field_text(self, field, text):
        if field == FIELD_ROLLS:
            self.rolls = text
        elif field == FIELD_PASS:
            self.passphrase = text
        elif field == FIELD_PATH:
            self.custom_path = text

    # ---- input ----
    def visible_fields(self):
        fields = [FIELD_ROLLS, FIELD_LENGTH, FIELD_PASS, FIELD_TAB]
        if self.tab == "bip32":
            fields.append(FIELD_PATH)
        return fields

    def handle_key(self, ch):
        fields = self.visible_fields()
        text_field = self.focus in (FIELD_ROLLS, FIELD_PASS, FIELD_PATH)
        if ch in (9,):                                    # Tab
            self.focus = fields[(fields.index(self.focus) + 1) % len(fields)]
            self.cursor = len(self.field_text(self.focus))
        elif ch == curses.KEY_BTAB:                       # Shift-Tab
            self.focus = fields[(fields.index(self.focus) - 1) % len(fields)]
            self.cursor = len(self.field_text(self.focus))
        elif ch == 16:                                    # Ctrl-P
            self.show_private = not self.show_private
        elif ch == 1:                                     # Ctrl-A: more rows
            self.n_addresses = min(self.n_addresses + 5, 100)
        elif ch == 24:                                    # Ctrl-X: fewer rows
            self.n_addresses = max(self.n_addresses - 5, 5)
        elif ch in (curses.KEY_PPAGE,):
            self.scroll = max(0, self.scroll - 10)
        elif ch in (curses.KEY_NPAGE,):
            self.scroll += 10
        elif ch == curses.KEY_UP:
            self.scroll = max(0, self.scroll - 1)
        elif ch == curses.KEY_DOWN:
            self.scroll += 1
        elif self.focus == FIELD_LENGTH and ch in (curses.KEY_LEFT,
                                                   curses.KEY_RIGHT):
            step = 1 if ch == curses.KEY_RIGHT else -1
            self.length_i = (self.length_i + step) % len(LENGTHS)
        elif self.focus == FIELD_TAB and ch in (curses.KEY_LEFT,
                                                curses.KEY_RIGHT):
            step = 1 if ch == curses.KEY_RIGHT else -1
            self.tab_i = (self.tab_i + step) % len(TAB_ORDER)
        elif text_field:
            text = self.field_text(self.focus)
            self.cursor = min(self.cursor, len(text))
            if ch in (curses.KEY_BACKSPACE, 127, 8):
                if self.cursor > 0:
                    text = text[:self.cursor - 1] + text[self.cursor:]
                    self.cursor -= 1
            elif ch == curses.KEY_DC:
                text = text[:self.cursor] + text[self.cursor + 1:]
            elif ch == curses.KEY_LEFT:
                self.cursor = max(0, self.cursor - 1)
            elif ch == curses.KEY_RIGHT:
                self.cursor = min(len(text), self.cursor + 1)
            elif ch == curses.KEY_HOME:
                self.cursor = 0
            elif ch == curses.KEY_END:
                self.cursor = len(text)
            elif 32 <= ch < 127:
                c = chr(ch)
                if self.focus == FIELD_ROLLS and c not in "123456 ":
                    curses.beep()
                    return
                if c == " " and self.focus == FIELD_ROLLS:
                    return                                # ignore spaces
                text = text[:self.cursor] + c + text[self.cursor:]
                self.cursor += 1
            self.set_field_text(self.focus, text)

    # ---- drawing ----
    def draw(self, scr, pending=False):
        scr.erase()
        h, w = scr.getmaxyx()
        if h < 14 or w < 46:
            scr.addstr(0, 0, "terminal too small")
            scr.refresh()
            return
        bold = curses.A_BOLD
        rev = curses.A_REVERSE
        dim = curses.A_DIM

        def put(y, x, text, attr=0):
            if 0 <= y < h:
                scr.addnstr(y, x, text, max(0, w - x - 1), attr)

        put(0, 0, " BIP39 DICE TOOL ".center(w - 1, "="), bold)

        # --- fields ---
        cursor_pos = None

        def field_line(y, label, value, field, hint=""):
            nonlocal cursor_pos
            focused = self.focus == field
            put(y, 1, label, bold if focused else 0)
            x = 1 + len(label) + 1
            attr = rev if focused else 0
            put(y, x, value + " ", attr)
            if hint:
                put(y, min(x + len(value) + 3, w - len(hint) - 2), hint, dim)
            if focused and field in (FIELD_ROLLS, FIELD_PASS, FIELD_PATH):
                cursor_pos = (y, min(x + self.cursor, w - 2))

        field_line(1, "Dice rolls (1-6):", self.rolls, FIELD_ROLLS)
        field_line(2, "Mnemonic length :", str(self.length), FIELD_LENGTH,
                   "</> raw 12 15 18 21 24")
        field_line(3, "BIP39 passphrase:", self.passphrase, FIELD_PASS)
        field_line(4, "Derivation      :", TABS[self.tab]["label"], FIELD_TAB,
                   "</> to change")
        row = 5
        if self.tab == "bip32":
            field_line(5, "Custom path     :", self.custom_path, FIELD_PATH)
            row = 6
        put(row, 0, "-" * (w - 1), dim)
        put(row + 0, 2, " Tab:next field  ^P:show/hide private  ^A/^X:rows"
                        "  arrows/PgUp/PgDn:scroll  q:quit ", dim)

        # --- body ---
        body_top = row + 1
        body_h = h - body_top
        if pending:
            put(body_top + 1, 4, "... calculating ...", bold | curses.A_BLINK)
            put(body_top + 3, 4, "(results clear while inputs change; they",
                dim)
            put(body_top + 4, 4, " reappear the moment you stop typing)", dim)
            if cursor_pos:
                curses.curs_set(1)
                try:
                    scr.move(*cursor_pos)
                except curses.error:
                    pass
            else:
                curses.curs_set(0)
            scr.refresh()
            return
        lines = report_lines(self.state(), width=w - 6,
                             show_private=self.show_private)
        max_scroll = max(0, len(lines) - body_h)
        self.scroll = min(self.scroll, max_scroll)
        for i in range(body_h):
            j = self.scroll + i
            if j >= len(lines):
                break
            text = lines[j]
            attr = 0
            if text and not text.startswith(" ") and not text.startswith("!!"):
                attr = bold
            if text.startswith("!!"):
                attr = bold | curses.A_UNDERLINE
            put(body_top + i, 1, text, attr)
        if max_scroll:
            pct = int(100 * self.scroll / max_scroll)
            put(h - 1, w - 12, f"[{pct:3d}%]", dim)

        if cursor_pos:
            curses.curs_set(1)
            try:
                scr.move(*cursor_pos)
            except curses.error:
                pass
        else:
            curses.curs_set(0)
        scr.refresh()

    def _read_key(self, scr, block=True):
        """getch with a manual ESC-sequence fallback for terminals whose
        arrow/page keys arrive as raw escape sequences curses doesn't map.
        With block=False, returns None immediately when no key is pending."""
        if not block:
            scr.nodelay(True)
            try:
                ch = scr.getch()
            finally:
                scr.nodelay(False)
            if ch == -1:
                return None
        else:
            ch = scr.getch()
        if ch != 27:
            return ch
        scr.nodelay(True)
        seq = ""
        try:
            for _ in range(3):
                nxt = scr.getch()
                if nxt == -1:
                    break
                seq += chr(nxt) if 0 <= nxt < 256 else ""
        finally:
            scr.nodelay(False)
        table = {
            "[A": curses.KEY_UP, "OA": curses.KEY_UP,
            "[B": curses.KEY_DOWN, "OB": curses.KEY_DOWN,
            "[C": curses.KEY_RIGHT, "OC": curses.KEY_RIGHT,
            "[D": curses.KEY_LEFT, "OD": curses.KEY_LEFT,
            "[5~": curses.KEY_PPAGE, "[6~": curses.KEY_NPAGE,
            "[H": curses.KEY_HOME, "[F": curses.KEY_END,
            "[3~": curses.KEY_DC, "[Z": curses.KEY_BTAB,
        }
        return table.get(seq, -1)

    def _inputs_key(self):
        return (self.rolls, self.length, self.passphrase, self.tab,
                self.custom_path, self.n_addresses)

    def run(self, scr):
        curses.use_default_colors()
        scr.keypad(True)
        while True:
            if self._inputs_key() != self._cache_key:
                # Inputs changed: show them instantly with results cleared
                # ("... calculating ...") so every keypress visibly lands,
                # then absorb any type-ahead before recomputing once.
                self.draw(scr, pending=True)
                ch = self._read_key(scr, block=False)
                if ch is None:
                    self.state()              # the heavy compute
                    continue
            else:
                self.draw(scr)
                ch = self._read_key(scr, block=True)
            # Drain any burst of pending keys (e.g. pasted rolls) so the
            # expensive recompute + redraw happens once per burst.
            while ch is not None:
                if ch == 17:                              # Ctrl-Q always quits
                    return
                if ch == ord("q") and self.focus not in (
                        FIELD_ROLLS, FIELD_PASS, FIELD_PATH):
                    return
                if ch != -1:
                    self.handle_key(ch)
                ch = self._read_key(scr, block=False)

# ======================================================================
# main
# ======================================================================

def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--selftest", action="store_true",
                    help="run embedded official test vectors and exit")
    ap.add_argument("--report", action="store_true",
                    help="non-interactive: print full report and exit")
    ap.add_argument("--rolls", default="", help="dice rolls, digits 1-6")
    ap.add_argument("--length", default="raw",
                    help="raw, 12, 15, 18, 21 or 24 (default raw)")
    ap.add_argument("--passphrase", default="", help="BIP39 passphrase")
    ap.add_argument("--tab", default="bip84", choices=TAB_ORDER,
                    help="derivation scheme (default bip84)")
    ap.add_argument("--path", default="m/0",
                    help="custom path when --tab bip32")
    ap.add_argument("--addresses", type=int, default=10,
                    help="number of addresses to derive (default 10)")
    ap.add_argument("--show-private", action="store_true",
                    help="include WIF private keys in --report output")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(0 if selftest() else 1)

    length = args.length if args.length == "raw" else int(args.length)
    if length not in LENGTHS:
        sys.exit("length must be raw, 12, 15, 18, 21 or 24")

    if args.report:
        state = compute(args.rolls, length, args.passphrase, args.tab,
                        args.path, args.addresses)
        print("\n".join(report_lines(state, show_private=args.show_private)))
        return

    tui = Tui()
    tui.rolls = "".join(c for c in args.rolls if c in "123456")
    tui.length_i = LENGTHS.index(length)
    tui.passphrase = args.passphrase
    tui.tab_i = TAB_ORDER.index(args.tab)
    tui.custom_path = args.path
    tui.n_addresses = args.addresses
    tui.cursor = len(tui.rolls)
    curses.wrapper(tui.run)

if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:            # e.g. `--report | head`
        import os
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(130)
