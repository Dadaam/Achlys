// les imports ils sont looooongs y'en a des choses
use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    feedbacks::{CrashFeedback, ConstFeedback},
    inputs::{HasTargetBytes, BytesInput},
    observers::StdMapObserver,
    state::StdState,
    schedulers::QueueScheduler,
    fuzzer::{Fuzzer, StdFuzzer},
    executors::{inprocess::InProcessExecutor, ExitKind},
    events::SimpleEventManager,
    monitors::SimpleMonitor,
    generators::RandPrintablesGenerator,
    mutators::{havoc_mutations::havoc_mutations, scheduled::HavocScheduledMutator},
    stages::mutational::StdMutationalStage,
};

use libafl_bolts::{
    current_nanos,
    rands::StdRand,
    tuples::tuple_list,
    AsSlice, // lecture de buffers
};

use std::path::PathBuf;
use std::ptr::addr_of_mut;
use std::num::NonZero;
use std::ffi::CString;
use std::os::raw::{c_char, c_void};

static mut DUMMY_MAP: [u8; 16] = [0;16]; // blackbox

#[link(name="cjson_blackbox")]
unsafe extern "C" {
    fn cJSON_Parse(value: *const c_char) -> *mut c_void;
    
    fn cJSON_Delete(c: *mut c_void);
}


fn main() {
    let observer = unsafe { // collecte de données, unsafe car manipulation de mémoire directe
        let ptr = addr_of_mut!(DUMMY_MAP) as *mut u8;
        let slice = std::slice::from_raw_parts_mut(ptr, 16);  // convertir en slice
        StdMapObserver::new("dummy_map", slice) 
    };
    
    let mut feedback = ConstFeedback::new(true); // on MEEEEEEENT vu qu'on est en blackbox
    let mut objective = CrashFeedback::new(); // détecter le crash 

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()), // on utilise les nanosecondes pr la seed 
        InMemoryCorpus::<BytesInput>::new(), // les données, on précise BYTES sinn il pète son crâne
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(), // stocker les crashs 
        &mut feedback, // on link ce que y'avait au dessus
        &mut objective,
    ).unwrap();

    let scheduler = QueueScheduler::new(); // file d'attente

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective); // reçoit le tout

    // Le harness reçoit un input (donnée générée par le fuzzer)
    let mut harness = |input: &BytesInput| {
        // On récup les données brutes
        let target = input.target_bytes();
        let buf = target.as_slice();

        // cJSON parser  
        if let Ok(c_str) = CString::new(buf) {
            unsafe {
                let parsed_json = cJSON_Parse(c_str.as_ptr()); // call the C function

                if !parsed_json.is_null() { // valid JSON! 
                    cJSON_Delete(parsed_json);
                }
            }
        }
        
        ExitKind::Ok // it's alr 
    };
    
    let mon = SimpleMonitor::new(|s| println!("{s}")); // afficher les msg dans la console
    let mut mgr = SimpleEventManager::new(mon); // gérer les events 

    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    ).expect("Impossible de créer l'Executor...");

    let mut generator = RandPrintablesGenerator::new(NonZero::new(32).unwrap()); // On genere des string aleatoires de 32 octets max
    
    let mutator =HavocScheduledMutator::new(havoc_mutations()); // génère les mutations, standard par de AFL++
    
    let mut stages = tuple_list!(StdMutationalStage::new(mutator)); // stages initialisés 

    state.generate_initial_inputs(
        &mut fuzzer, 
        &mut executor,
        &mut generator, 
        &mut mgr, 
        8 // nb inputs au départ
    ).expect("Impossible d'avoir les inputs initiaux");

    println!("Mamma mia ! CA TOURNE SUUUUUUUUUUUUUUUUU 🎉");

    fuzzer.fuzz_loop(
        &mut stages,
        &mut executor,
        &mut state,
        &mut mgr
    ).expect("Erreur fatale dans la fuzzing loop")
}


