// les imports ils sont looooongs y'en a des choses
use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    feedbacks::{CrashFeedback, MaxMapFeedback},
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
use std::slice::from_raw_parts_mut;

const MAX_EDGES: usize = 65536;

#[link(name = "cjson_graybox")]
unsafe extern "C" {
    fn cJSON_Parse(value: *const c_char) -> *mut c_void;
    fn cJSON_Delete(c: *mut c_void);

    static mut EDGES_MAP: [u8; MAX_EDGES]; 
    static mut EDGES_COUNT: std::ffi::c_ulong;
}



fn main() {
    let observer = unsafe { // collecte de données, unsafe car manipulation de mémoire directe
        let count = if EDGES_COUNT > 0 {EDGES_COUNT as usize} else { MAX_EDGES };
        let ptr = addr_of_mut!(EDGES_MAP) as *mut u8;
        let slice = from_raw_parts_mut(ptr, count);
        StdMapObserver::new("edges_map", slice) 
    };
    
    let mut feedback = MaxMapFeedback::new(&observer); 
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


