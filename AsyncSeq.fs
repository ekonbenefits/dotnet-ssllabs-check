// ----------------------------------------------------------------------------
// F# async extensions (AsyncSeq.fs)
// (c) Tomas Petricek, 2011, Available under Apache 2.0 license.
// Excerpt from https://github.com/fsprojects/FSharp.Control.AsyncSeq
// * Modified mapAsyncParallel to mapAsyncParallelUnordered for unordered results by Jay Tuley 7/17/2019
// ----------------------------------------------------------------------------

module AsyncSeq

open System
open System.Threading.Tasks
open FSharp.Control


[<AutoOpen>]
module internal Utils = 
    type Microsoft.FSharp.Control.Async with 
        static member bind (f:'a -> Async<'b>) (a:Async<'a>) : Async<'b> = async.Bind(a, f)

        static member awaitTaskCancellationAsError (t:Task<'a>) : Async<'a> =
          Async.FromContinuations <| fun (ok,err,_) ->
            t.ContinueWith (fun (t:Task<'a>) ->
              if t.IsFaulted then err t.Exception
              elif t.IsCanceled then err (OperationCanceledException("Task wrapped with Async has been cancelled."))
              elif t.IsCompleted then ok t.Result
              else failwith "invalid Task state!") |> ignore

        static member map f a = async.Bind(a, f >> async.Return)

    module Task =
        let inline join (t:Task<Task<'a>>) : Task<'a> =
             t.Unwrap()

        let inline extend (f:Task<'a> -> 'b) (t:Task<'a>) : Task<'b> =
            t.ContinueWith f    

        let chooseTaskAsTask (t:Task<'a>) (a:Async<'a>) = async {
            let! a = Async.StartChildAsTask a
            return Task.WhenAny (t, a) |> join }

        let chooseTask (t:Task<'a>) (a:Async<'a>) : Async<'a> =
            chooseTaskAsTask t a |> Async.bind Async.awaitTaskCancellationAsError

        let taskFault (t:Task<'a>) : Task<'b> =
            t 
            |> extend (fun t -> 
                let ivar = TaskCompletionSource<_>()
                if t.IsFaulted then
                    ivar.SetException t.Exception
                ivar.Task)
            |> join


let mapAsyncParallelUnordered (f:'a -> Async<'b>) (s:AsyncSeq<'a>) : AsyncSeq<'b> = asyncSeq {
  use mb = MailboxProcessor.Start (fun _ -> async.Return())
  let! err =
    s 
    |> AsyncSeq.iterAsyncParallel (fun a -> async {
      let! b = f a
      mb.Post (Some b) })
    |> Async.map (fun _ -> mb.Post None)
    |> Async.StartChildAsTask
  yield! 
    AsyncSeq.replicateUntilNoneAsync (Task.chooseTask (err |> Task.taskFault) (async.Delay mb.Receive))
  }