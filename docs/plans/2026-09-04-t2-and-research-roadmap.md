# Achlys : plan de reprise de T2 et trajectoire de recherche

Date : 4 septembre 2026. Statut : **plan détaillé, pas décision d’acceptation**.

Ce document précise l’ordre de travail du [Master Plan](../MASTER_PLAN.md), particulièrement ses sections 22, 23 et 30. Il sépare les faits observés, les corrections amorcées, les hypothèses et les choix proposés. Il ne constitue ni une nouvelle campagne de mesure ni une revue exhaustive ligne par ligne de tous les composants.

La dernière instruction du propriétaire est de **mettre uniquement le plan à jour**. L’implémentation est arrêtée. Les tâches ci-dessous ne sont pas réputées exécutées et ne constituent pas une autorisation automatique de lancer de nouvelles expériences, de publier une release ou de démarrer T3.

## 1. Mon avis sur la direction générale

La direction est bonne : établir un moteur fiable, mesurer la coopération entre stratégies, puis seulement apprendre à répartir le calcul. La séparation entre exécution rapide, admission canonique et vérification des crashs est un bon choix. Le refus de rendre le ML indispensable est également important : le projet doit rester utile si la génération neuronale n’apporte rien.

Le défaut principal du plan est son amplitude. Il décrit déjà des capsules, des artefacts de connaissance, des équipes temporaires, de la diffusion adaptative, des contrats de contraintes, des sondes et une synthèse de mutateurs alors que la preuve de robustesse de T2 reste incomplète. Je conserverais ces idées comme portefeuille de recherche, mais je cesserais de les traiter comme les composants obligatoires d’une même première version.

La question de recherche que je privilégie est : **à budget total égal, transmettre un obstacle précis et une petite quantité de connaissance réutilisable aide-t-il davantage que transmettre uniquement des seeds ?** C’est une hypothèse testable avec un périmètre raisonnable. Les gains, leur ampleur et la nouveauté scientifique restent à établir.

Je ne promets pas qu’Achlys battra AFL++. La première réussite crédible serait un système facile à reproduire, proche de son contrôle LibAFL, qui démontre un bénéfice spécifique sur une classe de difficultés annoncée à l’avance. Un résultat négatif bien isolé peut être utile ; un résultat positif obtenu en changeant simultanément le moteur, les ressources et la politique ne permet pas de conclure.

## 2. Comment lire le niveau de certitude

| Mention | Signification |
|---|---|
| **Constat** | Visible dans les fichiers ou dans un résultat effectivement consulté. La portée est limitée à cette observation. |
| **Correction amorcée** | Du code existe dans un commit local ; cela ne prouve pas son comportement complet. |
| **Hypothèse** | Explication plausible, avec un test nécessaire pour la confirmer ou la réfuter. |
| **Proposition** | Choix d’ingénierie recommandé, encore susceptible de changer. |
| **Question ouverte** | Information manquante ou arbitrage qui n’est pas tranché. |
| **Critère de sortie** | Preuve à obtenir avant de considérer un lot terminé. |

Un test unitaire réussi ne prouve ni la résistance à une mort de processus ni la performance. Un `cargo check` réussi ne remplace pas Clippy, la suite d’intégration ou un run release. Un fichier de résultats historique ne valide pas un binaire modifié depuis.

## 3. État exact au moment de l’arrêt

### 3.1 Références et limites de l’audit

Le dépôt `Dadaam/Achlys` a été récupéré sur `tranche-2-homogeneous`, initialement à `972a251a35aef2693ef5493dbb753a6ecbc75359`. Le pull était à jour lors de la vérification. Les références de ce plan portent sur cet état et les commits locaux ci-dessous, pas sur d’éventuelles modifications distantes ultérieures.

Les sources examinées comprennent le Master Plan, les décisions H0/T1/T2, les dossiers de preuve, les exemples H0/T1/T2, le stockage, le spool, l’autorité canonique, les replayers, le protocole et les scripts de validation. Les modules CLI et ML ont été examinés pour leurs implications architecturales, sans prétendre à une validation complète de leurs chemins expérimentaux.

L’état public reste **Level 0**. T1 est accepté comme infrastructure de baseline. T2 est ouvert et **non accepté**. T2, même terminé, ne démontrerait ni l’hétérogénéité, ni l’adaptation, ni une supériorité sur AFL++.

### 3.2 Changements déjà committés avant la consigne « uniquement le plan »

| Commit | Changement | Preuve disponible et limite |
|---|---|---|
| `162add3` | Protocole de clôture de T2 | Document de travail ; aucune acceptation. |
| `17e19be` | Correction du formatage du curseur de corpus | Correction ciblée de la dette de formatage ; ce n’est pas une preuve de CI complète. |
| `bbc3222` | Append du journal avec synchronisation ; récupération d’une dernière ligne interrompue | Test de troncature et de corruption d’une ligne terminée. Pas de test de coupure machine. |
| `8d7f4d4` | Publication d’un candidat dans un enregistrement indivisible ; migration des anciennes paires séparées | Tests de publication, doublon, corruption et paire héritée séparée. Migration réelle sous interruption à compléter. |
| `1e229c1` | Limite du spool, première provenance immuable, contrôle du hash à la lecture, récupération au-delà de la file bornée | Suite `achlys-core --lib` : **46 tests passés**. La contention réelle et les limites disque restent à mesurer. |
| `0688c60` | Réutilisation de l’état LibAFL, budget initial, publication sur admission locale, choix des cœurs visibles | `cargo check --example achlys_t2` réussi sur ces changements. Mort réelle du worker, intégration et performance non validées. |

Ces commits sont locaux dans l’environnement de travail. Ils ne doivent pas être décrits comme publiés, mergés ou couverts par une CI verte. Ils restent révisables ; une faiblesse de cette première implémentation est une raison de la corriger, pas de la protéger.

Une tentative de Clippy sur tout le workspace a été bloquée par l’environnement de compilation OpenSSL/pkg-config. Elle ne constitue ni un succès ni un diagnostic de défaut dans le code Rust. La préparation de dépendances a commencé, mais aucune validation globale réussie n’a été obtenue avant l’arrêt. Aucune nouvelle échelle Linux 5 × 300 s n’a été exécutée dans cette phase.

### 3.3 Brouillon de code mis de côté

Les modifications non committées du contrat d’entrée et des replayers ont été conservées séparément dans le stash Git `18f19517708a0d54e6d0ed286ab74e48a8ec87dd`, décrit comme `Paused replay-input draft before plan-only request, 2026-09-04`. Elles ne font pas partie du code actif.

Ce brouillon proposait un fichier temporaire anonyme pour stdin, une limite commune de 65 536 octets et une vérification plus stricte du résultat canonique. Il touchait `Cargo.lock`, `src/bridge/Cargo.toml`, `artifacts.rs`, `lib.rs`, `oracle.rs`, `sanitizer.rs`, un nouveau `replay_input.rs` et `src/protocol/src/manifest.rs`. Il n’a pas de validation finale exploitable. **Ne pas l’appliquer aveuglément** : le plafond et la classification des crashs canoniques doivent d’abord être décidés au lot T2-E.

Le stash est une sauvegarde locale, pas une référence distante durable. Avant de déplacer le travail vers un autre environnement, conserver explicitement cette référence ou exporter le brouillon. Ne pas modifier le code actif uniquement pour faire disparaître ce statut intermédiaire.

## 4. Ce que les mesures historiques disent réellement

Sources : [rapport Linux du 17 août](../evidence/t2/2026-08-17-linux-x86_64/REPORT.md), [A/B brut](../evidence/t2/2026-08-17-linux-x86_64/ab-7b2a40c/cells.tsv), [H0 indépendant](../evidence/t2/2026-08-17-linux-x86_64/h0-ceiling/results.tsv).

| Travailleurs | Médiane T2 optimisé, exec/s | Médiane H0 indépendant, exec/s | Ratio des médianes T2/H0 |
|---|---:|---:|---:|
| 1 | 763 618 | 768 079 | 99,42 % |
| 4 | 3 027 858 | 3 060 095 | 98,95 % |
| 8 | 4 465 579 | 4 593 914 | 97,21 % |

Il s’agit de **rapports entre médianes de séries distinctes**, pas de médianes de ratios appariés et pas d’intervalles de confiance. Ne pas mélanger ces estimateurs. Les séries A/B et H0 couvrent trois essais de 120 secondes sur `7b2a40c`. La vraie échelle historique de cinq essais de 300 secondes concerne `fcb725c`, antérieur à l’optimisation et au durcissement.

**Constat :** grouper les synchronisations a fortement amélioré le débit sur ce protocole. Le H0 indépendant plafonnait lui aussi près de 6× à huit travailleurs. Cela rend peu crédible l’explication « toute la non-linéarité vient d’Achlys ».

**Hypothèse assez solide pour cet hôte :** la saturation du matériel, de son allocation ou du moteur contribue largement au coude entre quatre et huit travailleurs. Cela ne permet pas d’isoler à distance la fréquence CPU, le cache, l’ordonnanceur, le quota, le voisinage de VM ou LibAFL comme cause unique.

**Limite importante :** cJSON est configuré ici avec `max_input_len = 64`, et les résultats restent autour de 171–173 arêtes. C’est une mesure de débit et de transport sur un petit contrat d’entrée. Elle ne démontre ni une meilleure recherche de bugs, ni la tenue de gros corpus, ni l’efficacité sur de longs fichiers structurés.

Le rapport historique disait qu’une dernière campagne sur `e2431ab` était en cours sur un autre hôte. Son résultat final n’est pas présent dans le dossier consulté. Cette phrase est une trace historique, pas une affirmation que le processus tourne encore. Si ces artefacts sont récupérés, les archiver comme preuve de ce commit, sans les attribuer à `0688c60` ou à un futur binaire.

## 5. Périmètre retenu pour T2

T2 doit établir un substrat homogène local : plusieurs travailleurs havoc, le même contrat d’exécution, un transport LLMP, une autorité canonique indépendante et une campagne récupérable. Il ne doit pas devenir une petite version de tout l’orchestrateur futur.

La diffusion en direct reste celle de LibAFL pour la nouveauté locale du même build. Les objets acceptés par l’autorité servent à la mesure et aux snapshots durables. `--join` signifie **continuation hors ligne d’une campagne arrêtée**, avec éventuellement de nouveaux slots. Ce n’est pas un attachement à un broker actif. La livraison sélective des deltas canoniques à des stratégies différentes appartient à T3/T4.

Je recommande de distinguer trois niveaux de reprise. Un crash intercepté par LibAFL doit permettre de restaurer l’état transmis par son gestionnaire. La mort brutale d’un travailleur sans snapshot exploitable doit au minimum préserver les objets déjà acceptés et permettre une continuation explicite. Une coupure machine exige un protocole de durabilité plus fort, notamment sur les répertoires ; elle n’est pas implicitement garantie par `sync_data` sur un fichier.

Pour T2, la garantie proposée couvre les **pannes de processus sur un système de fichiers local compatible**, avec erreurs explicites et récupération. La tolérance aux coupures électriques, au stockage réseau et à la disparition de l’hôte est différée. Cette restriction doit être écrite dans la documentation et dans les tests de reprise.

Le nom historique du gate « scaling quasi linéaire jusqu’à saturation » est trop ambigu. Il sera interprété par des métriques précises : comportement H0, surcoût T2 à ressources égales, courbes de scaling et couverture séparées. Aucun gain de débit ne sera appelé « gain utile de recherche » sans mesure d’un objectif de recherche.

## 6. Ordre de travail jusqu’à la clôture

| Lot | Objet | Dépend de | Statut actuel | Condition pour avancer |
|---|---|---|---|---|
| T2-A | État de référence et environnement | Rien | Partiellement fait | Binaire, outils, limites et tests de départ identifiés. |
| T2-B | Stockage, journal, migration | A | Corrections amorcées | Scénarios d’interruption et invariants de persistance démontrés. |
| T2-C | Vie des workers, reprise, supervision | B | Correction amorcée | Mort réelle, reprise, deadline et arrêt propres démontrés. |
| T2-D | Publication, provenance et charge | B, C | Correction amorcée | Origine fiable, coûts honnêtes, surcharge explicite, sans scan du corpus local. |
| T2-E | Entrées exactes et résultat des replays | A | Brouillon isolé | Aucun input tronqué silencieusement ; aucun blocage hors budget. |
| T2-F | Vérification des crashs T2 | C, E | À faire | Artefacts vérifiés et comptes reconstructibles. |
| T2-G | Intégration et instrumentation | B à F | À faire | Suite verte, sortie fiable, métriques définies. |
| T2-H | Expérience Linux figée | G | Non exécutée sur le nouveau code | Résultats complets, échecs conservés, comparaison contrôlée. |
| T2-I | Décision de clôture | H | À faire | Dossier de preuve et limitations confrontés au gate. |

L’ordre n’interdit pas une lecture ou une préparation indépendante. Il interdit de faire tourner la campagne finale pendant que le code mesuré change, ou de décider l’acceptation à partir de résultats partiels.

### T2-A. Fixer une référence reproductible

**Constat.** Le dépôt contient plusieurs chemins : CLI blackbox, H0/T1 in-process, T2 LLMP et modules ML historiques. Un build de l’exemple T2 ne couvre pas tout le workspace. L’environnement actuel expose neuf identifiants CPU, avec un quota cgroup de huit CPU équivalents ; cela ne prouve pas l’accès exclusif à huit cœurs physiques.

**Action proposée.** Partir d’un checkout propre et noter SHA, état dirty, Rust 1.97.1, versions de clang et du linker, dépendances natives et options de compilation. Vérifier les CPU autorisés, les topologies physique/logique si disponibles, les quotas et la mémoire. Déclarer les informations inconnues comme inconnues. Ne pas assimiler `nproc` à des cœurs physiques réservés.

**Validation.** Exécuter les gates existants avant d’imputer une régression aux nouveaux changements. Si une dépendance empêche un gate, conserver l’erreur et résoudre l’environnement. Ne pas retirer un crate du workspace ou assouplir les warnings pour obtenir artificiellement un succès.

**Sortie.** Un relevé d’environnement, les commandes exactes et un statut explicite pour chaque gate : réussi, échoué, bloqué ou non exécuté. Pas de statut « validé » global si seule une sous-suite a tourné.

### T2-B. Rendre la persistance démontrable

**Constat.** L’ancien transport pouvait déplacer les bytes et leur sidecar à des instants distincts. L’ancien lecteur du journal échouait sur une dernière ligne partielle. Les corrections introduisent des fichiers `.candidate` indivisibles et récupèrent la queue non terminée du journal. La récupération des objets au-delà de la file d’attente a également été corrigée.

**Contrat proposé.** L’identité d’un input est le hash de ses bytes exacts. Un doublon n’écrase pas sa première provenance retenue. Une publication est soit absente, soit complète et vérifiable. Le traitement d’un message peut être répété ; ses effets persistés doivent être idempotents. L’ack ne précède pas la persistance des informations nécessaires à la reprise.

**Points à vérifier dans les corrections actuelles.** L’objet, sa metadata et son événement ne constituent pas encore une transaction unique. Une panne entre ces écritures peut laisser un objet sans metadata ou sans `InputStored`. Il faut préciser si la récupération réconcilie ce cas ou l’arrête avec un diagnostic réparable. La conservation de la première metadata doit être confrontée à ces fenêtres, pas seulement au test de doublon normal.

Le journal doit traiter uniquement la dernière ligne non terminée comme append interrompu. Une corruption au milieu d’une ligne terminée doit arrêter la récupération et préserver les bytes pour diagnostic. L’archive de la queue interrompue doit éviter d’effacer la trace d’un incident précédent. Décider si un append complet mais invalide peut être isolé par une procédure explicite de réparation ; il ne doit jamais être ignoré automatiquement.

La migration des anciennes paires ne s’exécute que sans producteurs actifs. Elle doit être idempotente, supporter une nouvelle interruption et diagnostiquer bytes manquants, metadata manquante, doublons et hash faux. Ne pas supprimer la seule copie exploitable. Les temporaires abandonnés doivent être recensés et nettoyés seulement avec un critère d’inactivité sûr.

**Tests requis.** Interrompre après l’écriture du temporaire, après publication, après déplacement vers `processing`, après écriture de l’objet, après événement et avant ack. Répéter la récupération deux fois. Tester des doublons concurrents, une corruption d’objet, une queue interrompue avec UTF-8 incomplet et une ligne corrompue au milieu. Tester plus d’objets persistés que la taille de la file, pas seulement plus de fichiers dans l’inbox.

**Limite assumée.** La nouvelle récupération parcourt à nouveau les objets persistés pour recharger une file bornée. Elle corrige la perte, mais son coût peut croître fortement lors de gros redémarrages. Mesurer avant d’ajouter un index ou un journal de travail dédié. La borne de la file de replay ne signifie pas que les ensembles de hashes, `list_inputs()` ou l’ensemble de la campagne utilisent une mémoire constante.

**Sortie.** Aucun objet accepté perdu ou modifié dans les scénarios de processus retenus ; pas de duplication des décisions ; aucun travail oublié après vidage complet. Corruption et impossibilité de récupération produisent une erreur visible avec chemins et hashes utiles.

### T2-C. Restaurer le worker et superviser ses processus

**Constat.** Le callback ignorait auparavant l’état reçu du gestionnaire de redémarrage. Le commit `0688c60` le réutilise et porte cycles, séquence de production et nombre de reprises dans une metadata sérialisable. Le début du budget temporel est conservé en dehors du callback. Cela compile ; la reprise réelle n’a pas encore été exercée.

**Action proposée.** Construire un scénario de crash réel dans l’exécution in-process, après assez de travail pour rendre la reprise observable. Une injection déterministe réservée aux tests est acceptable si elle utilise le même chemin de signal/gestionnaire que le worker réel. Ne pas remplacer ce test par la création manuelle d’un événement `WorkerRestarted`.

La preuve doit montrer changement de PID, restauration d’état, maintien des objets acceptés, séquences non réutilisées et absence de rechargement complet des seeds comme si le worker était neuf. Comparer l’état enregistré autour d’un checkpoint ; ne pas exiger des sorties bit à bit identiques après une interruption asynchrone si le protocole ne le garantit pas.

La deadline inclut un nombre de reprises borné. Définir une limite de restarts et une raison de terminaison pour éviter une boucle de crash permanente. Le budget d’itérations compte actuellement des cycles LibAFL, pas des exécutions cible : le documenter et ne pas utiliser `--iters` comme budget de CPU. Tester séparément un budget temporel et un budget de cycles.

**Supervision à ajouter ou vérifier.** Refuser deux launchers écrivant la même campagne ; le verrou doit survivre aux races d’ouverture et être libéré par le noyau à la mort du propriétaire. Détecter la mort de l’autorité ; ne pas laisser les workers continuer sans limite en remplissant le disque. Borner l’attente finale de l’autorité et prévoir diagnostic, arrêt et récolte des processus enfants. Vérifier le comportement si le broker meurt ou si le parent reçoit SIGTERM.

Tester aussi SIGKILL. Sans snapshot, ce test peut se terminer par une campagne interrompue récupérable plutôt que par une reprise exacte du worker. Cette différence est acceptable si elle est annoncée, observable et n’efface pas le corpus accepté. L’intégrité d’un objet durable et la continuité de l’état RNG sont deux garanties distinctes.

**Risques à examiner.** Des compteurs créés dans le callback, notamment les publications et leur temps, repartent à zéro à la reprise alors que les exécutions restaurées peuvent être cumulées. Les notices de contrôle doivent être uniques après plusieurs redémarrages et conservées jusqu’à ack. Vérifier l’ordre `WorkerRegistered` / `CandidateDiscovered` / `WorkerLeft` lorsque le contrôleur prend du retard.

**Sortie.** Matrice de pannes réellement exécutée, durée totale bornée, pas de processus résiduel, pas de double écrivain et continuation hors ligne reproductible, y compris lorsqu’un nouveau slot charge le snapshot accepté.

### T2-D. Publier les vraies découvertes, avec une charge bornée

**Constat.** Le scan périodique du corpus local représentait encore 11–12 millions de chemins listés dans un essai historique à huit travailleurs. Le nouveau wrapper de mutateur publie lors d’une admission locale. Il cherche aussi le parent du testcase. Les imports LLMP ne doivent plus être attribués au destinataire comme des découvertes originales.

**Action proposée.** Vérifier que le hook couvre toutes les voies locales utilisées par T2 : mutations, seeds initiaux, restart et erreurs. Vérifier qu’il ne double pas les imports. Si un futur stage contourne ce hook, son contrat de publication devra être explicite ; ne pas supposer qu’un wrapper de mutateur couvre universellement tous les producteurs LibAFL.

Pour la première provenance, la notion correcte est « premier producteur dont la publication a été retenue par l’autorité ». Sans horloge causale commune, elle n’est pas forcément le premier découvreur physique. Pour T2, conserver cette règle suffit si elle est documentée. Pour T3/T5, ajouter des observations distinctes de découverte et d’import, sans dupliquer les bytes, afin de distinguer nouveauté, exploitation d’un input importé et crédit partagé.

Les parents manquants doivent être représentés comme inconnus. Les coûts non instrumentés ne valent pas zéro. `CandidateDiscovered` utilise encore `canonical_delta` comme `local_delta_count` et écrit des temps nuls : séparer ces sémantiques avant d’entraîner ou de comparer une politique. Préférer des champs optionnels/versionnés à une précision fictive. Les timestamps monotones locaux redémarrent avec le processus ; l’ordre du journal ou un identifiant d’époque doit porter la continuité inter-processus.

**Borne de transport.** Le code amorcé impose au chemin de publication une limite de 16 384 enregistrements et 128 MiB avec un verrou. Ce sont des valeurs initiales d’ingénierie, pas des seuils dérivés d’un benchmark. Auditer chaque chemin d’écriture, notamment overflow, migration et reprise. Mesurer taille réelle sérialisée, fichiers temporaires, notices et deltas. Un plafond de l’inbox seul ne borne pas le transport complet.

La mesure de quota parcourt les enregistrements du spool à chaque découverte. Cela retire le scan du corpus worker du chemin périodique, mais **pas toutes les lectures de répertoire**. Les métriques actuelles `paths_listed = 0` ne décrivent donc pas tout l’I/O de publication. Il faut instrumenter ce coût ou renommer les champs pour ne pas présenter un zéro trompeur. P95/max ne doivent pas être annoncés comme mesurés s’ils sont simplement remplis à zéro.

Je préfère initialement un échec explicite et récupérable quand l’autorité ne suit plus, ou une attente bornée hors exécution cible. Le choix doit être fixé avant la mesure. Ne pas abandonner silencieusement des candidats pour conserver un beau débit. Un compteur « queue pleine = 0 » sur cJSON court ne valide pas la politique de surcharge.

**Tests requis.** Autorité artificiellement lente ; mort d’un producteur tenant le verrou ; doublon venant de deux workers ; saturation en nombre et en bytes ; candidats de tailles variées ; corpus local volumineux ; input vide si le moteur peut en produire. Ce dernier cas doit être accepté selon le contrat ou rejeté comme configuration invalide, sans devenir une erreur surprise au milieu d’une campagne.

**Sortie.** Origine non réattribuée lors des imports, charge observée et bornée, erreurs explicites, et mesure avant/après du coût de publication. La localité de la nouveauté et l’autorité de la couverture restent distinctes.

### T2-E. Garantir les bytes et les délais des replays

**Constat.** Dans le code actif, les drivers canoniques lisent jusqu’à 65 536 octets et certains drivers sanitizer jusqu’à 4 096. Le replayer écrit stdin avant de commencer l’attente avec timeout. Un enfant qui ne lit pas peut donc bloquer pendant la livraison. Le dump canonique ne vérifie pas correctement tous les statuts de sortie et accepte actuellement un préfixe de bitmap.

**Proposition prioritaire.** Définir un seul contrat de longueur par cible et l’appliquer aux seeds, mutations, inputs restaurés et replays. Hash, bytes exécutés, longueur et résultat doivent décrire le même input. Tester les frontières 4 095/4 096/4 097 et 65 535/65 536/65 537, avec zéros binaires et un effet observable après la frontière.

Deux solutions sont ouvertes. La solution durable est un driver qui lit exactement les bytes autorisés par le manifeste et refuse explicitement tout excès. Un plafond commun fixe est plus simple pour T2, mais restreint les cibles et ne doit pas être introduit silencieusement. Le Master Plan montre un exemple à 1 MiB ; limiter le protocole entier à 64 KiB serait donc un changement de portée, pas une simple correction interne. Je privilégie une borne par manifeste dans les drivers, avec une limite de ressources maximale documentée.

Pour stdin, un fichier temporaire anonyme évite la contre-pression d’un pipe au moment de l’écriture. Une écriture asynchrone surveillée permet de rester sur des pipes, au prix d’une gestion plus délicate des threads et des descripteurs. Choisir après un petit test ciblé ; la vitesse de replay reste comptée dans le coût global. Dans les deux cas, borner aussi la préparation de l’entrée et le volume accepté.

Pour stdout/stderr, borner les bytes conservés tout en drainant les flux pour ne pas bloquer l’enfant. Enregistrer le fait d’une troncature et son seuil. Tuer/récolter le groupe de processus au timeout ; tester un descendant qui garde un pipe ouvert après la sortie du parent. Ne pas attendre indéfiniment un thread lecteur.

**Classification.** Une carte de mauvaise taille ou un format invalide est une défaillance de mesure. Un signal cible n’est pas automatiquement une panne d’infrastructure : conserver le candidat et l’envoyer à la vérification sanitizer, sans inventer de couverture si le dump n’a pas été produit. Une sortie non nulle peut faire partie du contrat d’une micro-cible ; elle doit être interprétée avec ce contrat. Ne pas corriger l’ancien silence en classant indistinctement tout statut non zéro comme erreur de l’oracle.

**Sortie.** Tests d’exactitude des entrées, timeout pendant livraison, sortie surdimensionnée, crash cible, non-zéro valide, binaire absent et descendant bloquant. Aucune troncature silencieuse et aucun bitmap partiel traité comme couverture complète.

### T2-F. Relier les crashs T2 à leur vérification

**Constat.** T1 possède ingestion, replay sanitizer et classification. T2 comptabilise des objectifs locaux mais son snapshot de métriques utilise encore les statistiques de crash par défaut. Il ne fournit donc pas à lui seul une chaîne complète de bugs vérifiés.

**Action proposée.** Extraire les fonctions communes minimales de T1 vers un module partagé, puis les utiliser après le drain de T2. Éviter de recopier plusieurs dizaines de lignes dans un troisième exemple. Garder le replay hors de la boucle rapide. À ce stade, une vérification de fin de campagne suffit ; un pool live de vérification peut attendre une nécessité mesurée.

Chaque candidat conserve son input exact, le build producteur, l’identité du sanitizer, l’environnement utile, le délai, la classe et les logs bornés. Distinguer fichiers candidats, inputs uniques, replays, crashs reproduits, signatures, timeouts et erreurs d’infrastructure. Une signature normalisée est un groupe de triage, pas la preuve d’une vulnérabilité unique.

La continuation doit retrouver les candidats non vérifiés et éviter le double comptage des vérifications déjà persistées. Si le build sanitizer change, ne pas réutiliser sans précaution une ancienne vérification. Si aucun crash n’est découvert, ne pas prétendre avoir démontré leur traitement : utiliser une cible déterministe et un candidat contrôlé.

**Sortie.** Un crash confirmé, un candidat propre, un non-zéro non crash, un timeout et une erreur d’environnement sont classés correctement ; les résultats reconstruits correspondent aux artefacts et les objets initiaux restent disponibles.

### T2-G. Stabiliser l’intégration et les métriques

**Gates à exécuter sur le même code final :** `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace --all-targets`, puis les scripts H0, T1 et T2 en mode fonctionnel. Enregistrer sorties et codes de retour. Les tests de panne complètent ces scripts ; ils ne sont pas remplacés par eux.

Le H0 fonctionnel compare ses traces/hashes déterministes de référence. Les campagnes multiworkers ne doivent pas promettre une séquence globale déterministe avec le même seed : l’ordonnancement et les échanges influencent leur trajectoire. Les assertions portent sur les invariants, les budgets et la reconstructibilité.

Le script T2 de smoke contient déjà beaucoup de logique de reprise et de manipulation d’artefacts. Mettre à jour ses fixtures pour les `.candidate`, sans supprimer les assertions devenues gênantes. Séparer progressivement les tests de stockage, lifecycle et CLI quand cela rend une défaillance identifiable. Ne pas engager une refonte générale pendant la préparation du benchmark.

Les anciens paramètres de synchronisation doivent avoir une sémantique honnête. `--rescan` est rejeté dans le code amorcé et `--sync-every` ne cadence plus la publication directe : actualiser aide, rapport et scripts. Un paramètre ignoré ne doit pas sembler piloter une expérience A/B active. Garder les anciennes valeurs seulement comme description des preuves historiques.

Mesurer au minimum exécutions cumulées, wall time monotone, temps CPU si disponible, taille et attente de la file, latence d’admission, bytes et nombre d’objets, publications, erreurs, reprises et temps de drain. Définir les unités et les champs absents. Utiliser les millisecondes du résultat ou une horloge monotone du runner ; le script historique retombe sur `date +%s`, trop grossier pour les petits runs.

**Sortie.** Checkout propre, gates fonctionnels passés, aucun champ trompeur et aucune ambiguïté connue dans le calcul du débit. Ce SHA devient le candidat pour T2-H.

### T2-H. Mesurer sans changer la question en cours de route

Le protocole historique 1/2/4/8 travailleurs, cinq essais de 300 secondes par cellule, reste le minimum proposé pour la clôture d’ingénierie. Ce n’est pas le protocole de release scientifique de 24 heures du Master Plan. Ne pas raccourcir une cellule après avoir vu son résultat.

| Contrôle | Ce qu’il mesure | Ce qu’il ne permet pas de conclure |
|---|---|---|
| LibAFL minimal vs Achlys H0 | Coût du substrat Achlys à un worker | Valeur du partage ou de l’orchestrateur multiworker. |
| N H0 indépendants vs T2 N | Coût pratique total et comportement sous les mêmes limites | Coût pur du transport, car le partage change aussi le corpus et les entrées exécutées. |
| T2 sur trajectoire contrôlée, avec/sans publication si nécessaire | Attribution d’une régression de transport | Gain de recherche sur une vraie campagne. |
| Couverture canonique et temps à objectif | Progression de recherche sur la cible déclarée | Généralisation à d’autres cibles ou classes de bugs. |

**Ressources.** Inclure broker, autorité, replay et workers dans le budget de T2. Le contrôle H0 dispose du même budget total. Si un cœur est réservé au contrôle, le compter ; ne pas offrir gratuitement un CPU supplémentaire à Achlys. Conserver les données de throttling lorsque disponibles. Une VM partagée produit de la preuve de développement ; elle ne devient pas un hôte contrôlé parce que l’OS est Linux.

**Appariement.** Même cible, mêmes bytes de seeds initiaux, longueur maximale, timeout, build fast, politique d’affinité, durée et série de seeds. Pour H0 indépendant, conserver la règle seed + slot utilisée par T2. Alterner l’ordre H0/T2 à l’intérieur des blocs et conserver cet ordre. Ne pas exécuter simultanément les groupes concurrents sur le même budget CPU pour gagner du temps.

**Budget minimal.** T2 seul représente 20 cellules × 300 s, soit 100 minutes de wall time séquentiel hors compilation et drain. Un contrôle H0 complet aux mêmes tailles et durées ajoute environ 100 minutes. Le coût des workers pour une méthode vaut 5 × 300 × (1 + 2 + 4 + 8) = 22 500 secondes de CPU alloué, soit 6,25 heures-cœur nominales. Ce n’est pas une mesure de CPU consommé ; le contrôle et les replays s’ajoutent pour T2.

**Sorties.** Conserver par cellule le SHA source, les hashes de binaires, le manifeste, l’environnement, la commande, l’ordre, la durée réelle, le code de retour, les compteurs et les logs. Une cellule ratée reste dans l’inventaire. Ne pas écraser un répertoire d’expérience existant. `T2_LADDER=RAN` veut dire exécution complète, pas acceptation ; ne pas l’écrire avant la fin des cellules.

**Calculs fixés avant exécution.** Définir `débit = somme des exécutions / wall time observé du groupe`, `speedup(N) = débit(N) / débit(1)` et `surcoût(N) = 1 - débit_T2(N) / débit_H0(N)`. Rapporter aussi durée de fuzzing et durée de drain séparées. Pour des essais appariés, publier les ratios individuels et leur médiane ; ne pas remplacer cet estimateur en cours de route par un ratio de médianes parce qu’il serait plus favorable.

Le budget de surcoût reste **5 %**, avec H0 à vérifier de nouveau. Les ratios multiworkers sont des diagnostics à interpréter avec leur distribution et le plafond indépendant. Avec cinq essais, une estimation proche du seuil est incertaine. Publier dispersion et intervalle d’incertitude approprié ; si le résultat chevauche matériellement le seuil, classer « inconclusif » et prévoir une répétition annoncée. Ne pas prétendre qu’un test non significatif prouve l’équivalence.

Une croissance non linéaire peut être acceptable si le contrôle indépendant montre le même plafond et si le surcoût satisfait le gate. À l’inverse, huit workers plus rapides qu’un seul ne suffisent pas à accepter T2 si la coordination coûte trop ou si l’admission accumule du retard.

**Extension de robustesse proposée.** Conserver cJSON/64 pour comparer avec l’historique et ajouter une expérience séparée avec des inputs plus longs et un corpus initial plus fourni. Fixer ces tailles après avoir décidé T2-E. Son rôle est de vérifier charge, I/O et débit du contrôleur, pas de remplacer une cellule historique défavorable. Les changements de difficulté de cible restent visibles.

**Sortie.** Tableau complet, analyse reproductible, historique des échecs et limites de l’hôte. Les résultats ne sont jamais extrapolés vers AFL++ ou les obstacles spécialisés.

### T2-I. Décider explicitement

Quatre issues sont possibles. **Accepté pour le périmètre T2** si invariants, intégration et surcoût passent avec une preuve suffisante. **À corriger** si un défaut de code ou de protocole est démontré. **Inconclusif** si la variabilité ou l’environnement empêche de juger le seuil. **Approche rejetée** si le transport choisi reste trop coûteux après une investigation raisonnable.

La décision doit énumérer ce qui est garanti : homogeneous LLMP local, entrée supportée, durabilité de processus, continuation hors ligne, reconstruction et limites testées. Elle doit également citer ce qui manque : attachement live, hétérogénéité, adaptation, comparaison publique, reprise après coupure machine si non testée.

Mettre ensuite seulement à jour README, architecture et dossier de preuves. Un accès à une machine plus contrôlée peut rester nécessaire pour une affirmation publique de performance, même après une acceptation fonctionnelle de développement. L’acceptation de T2 ne change pas automatiquement le niveau de réussite scientifique du projet.

## 7. Décisions d’architecture que je recommande, et celles que je diffère

### 7.1 À conserver

Conserver LibAFL comme moteur et LLMP pour la coopération homogène. Garder la couverture canonique hors du worker rapide. Conserver l’objet adressé par hash et un journal à écrivain unique. Préserver des corpora locaux indépendants : un input sans nouvelle arête canonique peut encore être utile à une stratégie. Garder un fonctionnement havoc seul et un repli statique quand une politique échoue.

Confiance : élevée sur la cohérence de ces choix avec le projet ; aucune garantie qu’ils soient optimaux en performance sans mesure. Une optimisation de stockage ou de replay reste possible après profilage.

### 7.2 À changer maintenant dans le plan

Remplacer « near-linear useful scaling » par les métriques et contrôles de T2-H. Définir la panne supportée avant de promettre « restart ». Faire remonter exactitude des entrées et supervision au niveau du gate. Distinguer origine de l’objet, observations de découverte et attribution de bénéfice. Faire de l’inconnu une valeur explicite dans les métriques.

La limite disque totale et la rétention doivent être une politique de campagne. On ne peut pas promettre une archive durable et une croissance infinie : fixer un budget, arrêter proprement avant saturation, ou exporter avec validation avant suppression. Le plafond du spool ne règle pas la croissance du corpus, du journal et des crashs.

### 7.3 À profiler avant de choisir

Le JSON par candidat est simple et inspectable, mais gonfle les bytes et ajoute de la sérialisation. Un format binaire, des segments append-only ou un transport mémoire peuvent être meilleurs à forte charge. Ne pas migrer tout le stockage avant de mesurer coût par publication, contention du verrou, I/O et retard d’admission.

Un oracle lancé en processus neuf est coûteux mais facilite l’isolation. Un forkserver ou un replay persistant peut améliorer le débit de contrôle ; il faut d’abord prouver que le reset d’état et la couverture sont équivalents. Ne pas accélérer l’oracle en réintroduisant une contamination d’un input au suivant.

L’horodatage et le checkpoint peuvent être améliorés sans base de données distribuée. Une base embarquée n’est justifiée que si les transactions ou index nécessaires deviennent plus simples et plus fiables qu’un protocole fichiers bien testé.

### 7.4 À différer

HTTP entre workers, broker multi-hôtes, consensus distribué, interface graphique avancée, remplacement de LibAFL, ordonnanceur neuronal, moteur symbolique maison et DSL universelle ne répondent pas au prochain gate. Les noter n’implique pas de créer maintenant tous leurs types.

## 8. Séparer première version utilisable et résultat scientifique

Le plan initial place distribution et CLI tard, après de nombreuses capacités. Je propose deux jalons, sans renuméroter artificiellement les tranches de recherche.

**Jalon U, version expérimentale utilisable.** Après T2 accepté, préparer une entrée CLI fidèle au chemin déjà mesuré, des erreurs compréhensibles, un exemple reproductible, une reprise documentée et un export de preuves. Faire une décision de périmètre distincte avant le travail. Une première version peut supporter un registre restreint de harnesses ; elle ne doit pas prétendre accepter arbitrairement toute bibliothèque C/C++.

Les adaptations CLI doivent être fines et réutiliser le runtime testé. Elles doivent repasser le contrôle H0/T2 si elles changent l’exécution. Ce jalon n’exige ni ML, ni concolique, ni adaptation, et ne donne pas le droit de présenter une victoire sur AFL++.

**Jalon R, release de recherche.** T8 reste le lieu d’une comparaison externe contrôlée, d’ablations, de scripts de reproduction et d’une classe de cibles supportées figée. Les tranches spécialisées qui n’apportent pas de valeur peuvent être rejetées sans bloquer à jamais la distribution du système utile.

Je ne ferais pas un dashboard avant de savoir exactement ce que signifient les compteurs. Je ne déplacerais pas non plus tout le code des exemples vers une architecture « finale » en même temps que je corrige la reprise. Extraire d’abord les fonctions effectivement partagées, puis créer une façade stable une fois le comportement vérifié.

## 9. Suite de recherche : une seule variable principale par étape

### T3. Portfolio statique : vérifier l’utilité des spécialistes

**Hypothèse H1.** Une allocation fixe havoc + comparaison apporte quelque chose par rapport au même budget homogène. Rien dans T2 ne l’a testé.

Commencer par une capacité comparaison et une baseline structurelle simple, en les introduisant séparément. Rendre les builds compatibles au niveau du harness et les métriques comparables via le replay canonique. Ne pas transférer une carte CmpLog comme si ses indices étaient ceux du build fast. Vérifier qu’un input rejeté pour nouveauté canonique ne disparaît pas de la vue locale s’il reste utile à son worker.

La grille initiale proposée est homogène, majorité havoc avec un spécialiste, puis une répartition plus équilibrée, sous un budget total fixe. Les nombres exacts dépendent du matériel et doivent être arrêtés avant la campagne. Ajouter des cibles sans obstacle spécialisé comme contrôle négatif : un système ne doit pas cacher le coût de son spécialiste sur les cas simples.

Mesurer couverture au cours du temps, atteinte de branches annoncées, coût par rôle, conversions de candidats spécialisés et crashs vérifiés si disponibles. Comparer aux configurations AFL++ pertinentes seulement une fois leurs contrats et budgets alignés.

Le « meilleur statique » doit être choisi sur un jeu de développement distinct de l’évaluation finale. Choisir après coup la meilleure répartition par cible sur les mêmes essais de test crée un oracle de sélection. On peut publier cet oracle comme borne descriptive, mais pas comme une politique déployable.

**Sortie.** Gain reproductible sur une classe définie et absence de régressions cachées. Si rien ne gagne, améliorer la capacité ou revoir la cible avant T4/T5. Ne pas ajouter un bandit pour masquer un spécialiste inutile.

### T4. Assistance ciblée : réduire le problème transmis

**Hypothèse H2/H6.** Seed + obstacle explicite bat le partage aveugle. Je commencerais avec une capsule minimale : build, input, site de comparaison, observation, capability demandée, budget, résultat. Le schéma riche de la section 30 est un catalogue, pas le minimum à implémenter.

Construire trois traitements comparables : seed seule, seed avec metadata minimale, capsule enrichie. Fixer les ressources des spécialistes et la politique de routing. Sinon le test mélange richesse du message et allocation de calcul.

Introduire leases, identité de requête, expiration, déduplication et résultats typés. Une requête est une hypothèse du worker ; elle ne prouve pas que l’obstacle existe ou qu’un spécialiste sait le résoudre. Un timeout n’est pas une preuve d’insatisfiabilité et une panne d’infrastructure ne pénalise pas la compétence de la stratégie.

Ajouter la mémoire d’échecs avec une portée étroite : build, stratégie/version, forme d’obstacle, contexte pertinent, budget, délai de réessai. Réautoriser un essai lorsque la seed, les connaissances ou le budget ont changé de manière pertinente. Mesurer les faux blocages d’une solution future, pas seulement les appels économisés.

Les premiers artefacts de connaissance devraient être de petits objets déclaratifs, par exemple un token contextualisé ou une recette de comparaison. Tester séparément « seeds résolues seulement » et « mêmes seeds + artefact ». Tous les coûts de génération, validation, sérialisation et consommation entrent dans le budget.

**Sortie.** Chaîne requête → travail → résultat → validation reconstructible, répétition bornée, et bénéfice qui survit à l’ablation « metadata minimale ». Si les champs enrichis ne servent pas, les retirer.

### T5. Allocation adaptative : éviter l’attribution trompeuse

**Hypothèse H3.** L’adaptation peut dépasser une bonne politique statique sélectionnée honnêtement. Un portfolio qui progresse tout seul ne valide pas cette hypothèse.

Ordre recommandé : politique fixe, round-robin pondéré, règle simple à récompense décroissante, puis bandit non contextuel. Introduire un modèle contextuel seulement si les features sont stables et apportent un gain. Garder un plancher d’exploration havoc, un plafond spécialiste, une durée minimale de rôle et une hystérésis.

Commencer par router les tâches dans des pools stables avant de faire migrer les processus entre rôles. La migration change builds, caches et échauffement ; son coût complique l’expérience. Choisir une seule échelle de décision adaptative à la fois, plutôt que changer routing, diffusion et nombre de slots simultanément.

La couverture canonique donne une mesure commune, mais pas un crédit causal parfait. Un spécialiste peut fournir une seed dont un worker havoc exploite ensuite le potentiel ; la première admission ne résume pas ce bénéfice. Conserver lignée et observations, puis comparer quelques règles simples de crédit comme ablations. Ne pas présenter un score arbitraire comme « valeur marginale exacte ».

Conserver les composantes brutes de reward : nouveautés, coûts, tâches résolues, vérifications, retards. Comparer reward immédiate et retardée. Le délai de replay canonique peut pénaliser à tort certains rôles : enregistrer moment de production et moment de validation.

Les politiques fantômes peuvent aider à repérer famine ou oscillation. Elles ne permettent pas de rejouer exactement le monde qu’une autre allocation aurait créé. Une prétendue amélioration hors ligne doit être confirmée par des campagnes réelles.

**Sortie.** Évaluation hors sélection des paramètres, comparaison au meilleur statique effectivement choisi sur développement, ablations et coûts complets. Si le dynamique n’apporte pas un bénéfice robuste, garder la politique statique comme produit et enregistrer H3 non soutenue.

### T6. Concolique : payer uniquement les obstacles adaptés

**Hypothèse H4.** Un solveur borné peut rendre rentables certains obstacles que comparaison et structure simple ne résolvent pas. Je ne suis pas certain que son bénéfice agrégé compensera son coût sur les cibles envisagées.

Intégrer une capacité existante compatible avec LibAFL/SymCC après vérification des versions et artefacts officiels au moment de l’implémentation. Ne pas promettre aujourd’hui que leur intégration exacte sera simple. Limiter branches, requêtes, wall time et mémoire. Distinguer unsupported, timeout, insatisfiable dans le modèle, modèle incohérent et solution concrète valide.

Définir l’éligibilité avant le solve : site identifié, bytes contrôlables, trace compatible et gain attendu raisonnable. Comparer au spécialiste comparaison renforcé et à un calendrier concolique statique. Les solutions passent par le même replay exact et gardent leur build de trace.

Les contrats de contraintes commencent avec régions fixes et relations simples. Une réparation peut déplacer des offsets ou détruire une précondition. La validité finale doit être vérifiée par exécution ; une annotation « preserve » n’est pas une preuve.

**Sortie.** Bénéfice sur une classe annoncée, pas de budget incontrôlé, solutions reproductibles et limitation visible des cas unsupported. Sinon désactiver la capacité pour les cibles où elle ne rentabilise pas ses ressources.

### T7. ML : utiliser la tâche qui justifie le modèle

**Constat sur l’héritage.** `src/cortex/training/train.py` entraîne une LSTM bidirectionnelle sur une cible décalée d’un byte avec MSE. Pour une prétention de prédiction causale, le sens inverse a accès à des bytes futurs qui comprennent les labels de nombreuses positions. Une faible loss ne prouverait donc pas une capacité de génération causale. La régression de valeurs de bytes ne modélise pas non plus directement une distribution catégorielle.

Ne pas relancer cet entraînement comme baseline scientifique. S’il est conservé pour une autre tâche, renommer et définir cette tâche ; sinon le désactiver clairement. Aucun changement ML n’est nécessaire pour terminer T2.

Ordre proposé : extraction hors ligne de dictionnaire ou de structure, prédiction légère de valeur d’une tâche, matching seed/worker, puis seulement génération ou synthèse de mutateurs. Une heuristique, un n-gramme ou une réparation structurale est souvent le contrôle le plus important.

Séparer le coût d’installation initiale et le coût par campagne, puis publier les deux. Compter entraînement, CPU, GPU, appels, latence, validation et échecs. Pour amortir un modèle, annoncer combien de campagnes sont supposées partager le coût ; ne pas le rendre gratuit par convention implicite.

Faire des splits par projet ou famille, pas uniquement par fichier ou campagne d’une même cible. Vérifier duplication de corpus et partage de code. Pour les modèles préentraînés, ne pas promettre d’exclure toute connaissance préalable d’une cible publique sans preuve ; distinguer contamination contrôlable de l’évaluation et exposition de préentraînement inconnue.

Pour une synthèse de skill, préférer des opérations bornées et déclaratives. Valider hors des seeds ayant servi à la produire, vérifier limites d’exécution et de sortie, puis faire un A/B de campagne. La DSL n’est à construire que si les opérateurs fixes se révèlent insuffisants.

**Sortie.** Valeur marginale après coûts et baseline bon marché, ou retrait explicite de la capacité. Une bonne perplexité, beaucoup d’inputs valides ou une démonstration spectaculaire isolée ne suffisent pas.

### T8. Évaluation externe et distribution

Figer une classe supportée, les harnesses, leurs révisions, les configurations des baselines et le protocole avant de regarder le résultat final. Utiliser les conventions FuzzBench lorsque pertinentes et une suite à bugs connus si l’objectif est la découverte de bugs. Vérifier au moment de l’exécution la disponibilité et la compatibilité des suites : elles ne sont pas garanties par une mention dans le plan.

La cible reste environ vingt essais de vingt-quatre heures pour une revendication de release, avec exceptions justifiées avant campagne. Le coût est élevé ; commencer par le développement et les candidatures plus courtes pour éliminer les mauvaises idées. Un budget insuffisant réduit la portée de la conclusion, pas le droit de sélectionner les meilleurs essais.

Conserver effets par cible, médianes, incertitude, analyses de temps à événement avec essais non résolus censurés, et distinction entre exécutions répétées et unités réellement indépendantes. Ne pas transformer les millions de mutations d’une seule campagne en millions d’échantillons statistiques.

La sortie publiable comprend installation, tutoriel, manifests, scripts d’analyse, résultats bruts, crashs/ground truth autorisés, hashes et limitations. Une reproduction extérieure est plus importante qu’un nouveau composant de présentation.

## 10. Portefeuille des paris : priorités et doutes

Aucune nouveauté des paris ci-dessous n’est établie par cette mise à jour. La bibliographie du Master Plan est une liste à vérifier ; aucune nouvelle revue systématique de littérature n’a été menée ici. Les étiquettes historiques « High » ou « Medium-high » de nouveauté étaient trop assurées pour le niveau de preuve disponible.

| Pari | Position proposée | Pourquoi cela peut aider | Ce qui pourrait l’invalider |
|---|---|---|---|
| Frontier Capsules | Priorité recherche 1, minimum en T4 | Éviter de refaire le contexte d’un obstacle. | Seed + deux champs fait aussi bien ; coût de contexte supérieur au gain. |
| Knowledge Artifacts | Priorité recherche 2, un type simple d’abord | Amortir un solve sur les mutations futures. | Artefact trop spécifique, propagation chère, aucune valeur au-delà de la seed résolue. |
| Failure Memory | Mécanisme étroit dès les leases, ablation dédiée | Éviter les répétitions identiques coûteuses. | Cache trop large qui empêche une réussite après changement de contexte. |
| Frontier Teams | Reporter après bénéfice du routing simple | Composer des compétences autour d’une difficulté. | Allocation à plusieurs niveaux trop complexe ; pools stables aussi efficaces. |
| Adaptive Diffusion | Reporter ; comparer d’abord îlots fixes et broadcast | Préserver de la diversité quand elle est réellement utile. | Retarder une découverte coûte plus que la diversité gagnée ; corpora différents sans progrès utile. |
| Constraint Contracts | T6, relations simples seulement | Réduire les réparations qui se détruisent entre elles. | Dépendances de bytes trop couplées ou validation aussi chère qu’un nouveau solve. |
| Active Probing | Expérience isolée après observation d’erreurs de routing | Acquérir l’information qui manque au choix de stratégie. | CmpLog, taint ou perturbations simples suffisent ; coût jamais amorti. |
| Scout Tournaments | Faible priorité avant incertitude mesurée du routing | Tester brièvement des capacités quand le choix est ambigu. | Double travail systématique ; signaux précoces sans lien avec le résultat final. |
| Mutation Skill Synthesis | T7 optionnel, risque élevé | Réutiliser une transformation produite rarement. | Réinvente dictionnaire/réparation existante ; modèle et validation trop chers. |
| Cross-campaign Prior | Après suffisamment de campagnes comparables | Réduire le démarrage à froid. | Fuite par famille de cible, transfert négatif, features instables. |
| Shadow Policy Laboratory | Outil de diagnostic après politiques simples | Écarter famine et oscillations avant un gros run. | Estimations contrefactuelles trompeuses, logs trop incomplets pour estimer quoi que ce soit. |

Mon choix est de financer intellectuellement le couple **capsule minimale + artefact réutilisable simple**, tout en gardant la mémoire d’échecs comme infrastructure mesurée. Je suis moins convaincu par l’intérêt immédiat des équipes, des scouts et du prior inter-campagnes : ils ajoutent des degrés de liberté avant d’avoir démontré le besoin. Cette préférence est un jugement de priorité, pas une mesure de supériorité.

Avant une revendication de nouveauté, réaliser la comparaison mécanisme par mécanisme avec les travaux cités dans le Master Plan et leurs suites pertinentes. Chercher les équivalents même lorsqu’ils utilisent d’autres mots. S’il existe déjà une solution équivalente, la reproduire comme baseline et reformuler la contribution au lieu de préserver artificiellement le vocabulaire Achlys.

## 11. Inconnues qui peuvent réellement changer le plan

| Question | Pourquoi elle compte | Comment la résoudre | Décision par défaut en attendant |
|---|---|---|---|
| Où sont les résultats finaux `e2431ab` ? | Peuvent compléter l’historique de robustesse. | Récupérer les artefacts originaux et vérifier SHA/protocole. | Aucun statut final supposé. |
| Quel matériel contrôlé sera disponible ? | Affecte l’interprétation du seuil de 5 % et le coût des campagnes. | Relevé d’affinité, quota, topologie, charge et conditions de partage. | Hôte actuel = preuve de développement. |
| Quelle reprise LibAFL est réellement garantie pour chaque signal ? | Détermine la promesse « restart ». | Reproducer de mort réelle et inspection de la version utilisée. | Garantie minimale sur corpus durable ; état exact seulement si testé. |
| Quelle longueur d’input la première version doit-elle supporter ? | Change les drivers, les bounds et la diversité des cibles. | Choisir les cibles puis un manifeste cohérent. | Pas de troncature silencieuse ; pas de plafond global ajouté par surprise. |
| Le contrôleur suit-il un corpus réellement volumineux ? | Peut imposer un autre format ou un replay plus rapide. | Test de charge séparé avec latences, tailles et quotas. | Stockage simple ; échec explicite si surcharge. |
| Quel coût manque dans les événements ? | Empêche de juger la valeur d’une stratégie. | Cartographie mesure/source/unité/absence. | Inconnu explicite ; pas de reward apprise dessus. |
| Le partage homogène réduit-il une diversité utile ? | Conditionne la diffusion future. | Comparer broadcast, indépendants et îlots fixes à budget égal. | LLMP standard pour T2 ; pas de diffusion adaptative. |
| Quel obstacle réel justifie un spécialiste ? | Empêche des démonstrations uniquement synthétiques. | Jeu de développement divers, difficulté observable et contrôle négatif. | CmpLog d’abord ; concolique/ML différés. |
| Quelle part de la première CLI doit être générale ? | Peut transformer un petit jalon utilisable en refonte de harnesses. | Décision de support explicite après T2. | Registre limité et honnête plutôt que promesse universelle. |
| Les capsules apportent-elles plus qu’une metadata minimale ? | Détermine la taille de la contribution centrale. | Ablation seed / metadata / capsule. | Schéma minimal extensible, sans tous les types futurs. |

## 12. Commits et passage de relais

Garder des commits atomiques par contrat, avec l’assertion de comportement et sa preuve. Une séquence future raisonnable est : reprise du stockage et des tests de panne ; lifecycle/supervision ; provenance et charge ; contrat d’entrée ; crashs ; instrumentation ; runner de benchmark ; preuves ; décision documentaire. Séparer une amélioration de sémantique d’un changement de protocole de performance lorsque c’est possible.

Un commit qui change le chemin mesuré invalide l’attribution de la campagne suivante à l’ancien SHA. Les optimisations, flags et modes de contrôle sont figés avant lancement. Les résultats bruts et leur analyse doivent pouvoir être reliés au commit exact, sans importer un graphique généré depuis un autre état.

À chaque lot, indiquer fichiers touchés, invariant, test réellement exécuté, résultat, limite et prochain risque à résoudre. Si une hypothèse est réfutée, modifier ce plan avec le motif. Ne pas compléter les cases par des intentions.

Pour reprendre après cette mise à jour : relire l’état Git, les six commits déjà présents et le brouillon isolé ; traiter d’abord les lacunes de leurs contrats ; obtenir les validations de T2-A à G ; figer ensuite seulement T2-H. **Aucune étape de T3 n’est prête à être déclarée commencée ou autorisée par le simple fait que ce plan la décrit.**
