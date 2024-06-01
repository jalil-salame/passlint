/// Print a warning and do an action (return, continue, etc)
///
/// ```rust
/// warn!(try_foo(); else continue "failed to foo ({}): {err}", data);
/// ```
#[macro_export]
macro_rules! warn {
    ($res:expr; else continue $fmt:literal $($arg:tt)*) => {
        match $res {
            Ok(res) => res,
            Err(err) => {
                eprintln!($fmt $($arg)*, err = err);
                continue;
            },
        }
    };
    ($res:expr; else $ret:expr => $fmt:literal $($arg:tt)*) => {
        match $res {
            Ok(res) => res,
            Err(err) => {
                eprintln!($fmt $($arg)*, err = err);
                $ret
            },
        }
    };
    ($res:expr; else return $ret:expr => $fmt:literal $($arg:tt)*) => {
        match $res {
            Ok(res) => res,
            Err(err) => {
                eprintln!($fmt $($arg)*, err = err);
                return $ret;
            },
        }
    };
}

#[macro_export]
macro_rules! timeit {
    ($msg:literal; $cmd:expr) => {{
        let now = std::time::Instant::now();
        print!($msg);
        let res = $cmd;
        let elapsed = now.elapsed();
        let (unit, amount) = $crate::macros::human_time(elapsed);
        println!(": took {amount:.3}{unit}");
        res
    }};
}

/// Returns a unit and an f64 representing the quantity of that unit to make it easier to see the
/// relevant information.
#[doc(hidden)]
pub(crate) fn human_time(elapsed: std::time::Duration) -> (&'static str, f64) {
    if elapsed.as_secs_f64() >= 1.0 {
        ("s", elapsed.as_secs_f64())
    } else if elapsed.subsec_nanos() > 1_000_000 {
        ("μs", f64::from(elapsed.subsec_nanos()) / 1_000_000.0)
    } else if elapsed.subsec_nanos() > 1000 {
        ("μs", f64::from(elapsed.subsec_nanos()) / 1000.0)
    } else {
        ("ns", f64::from(elapsed.subsec_nanos()))
    }
}
