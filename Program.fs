(*
   Copyright 2019 Ekon Benefits

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*)
open System
open McMaster.Extensions.CommandLineUtils

let OptionToOption (opt:CommandOption<'T>) =
    if opt.HasValue() then
        opt.ParsedValue |> Some
    else
        None



[<EntryPoint>]
let main argv =
    use app = new CommandLineApplication();
    app.HelpOption() |> ignore;

    let optOutDir = app.Option<string>("-o|--output <DIRECTORY>", 
                                       "Output Directory for optional json data [Default: don't write out data]",
                                       CommandOptionType.SingleValue)

    let optEmoji = app.Option<bool>("--emoji", 
                                    "Use emoji's when outputing to console", 
                                    CommandOptionType.NoValue)
    
    let hosts = app.Argument<string>("Hosts", "Hosts to check SSL Grades and Validity", multipleValues=true).IsRequired();

    app.OnExecute(Func<int>(
                    fun ()->
                       hosts.Values
                       |> Check.sslLabs {OptOutputDir = (optOutDir |> OptionToOption) ; Emoji = optEmoji.HasValue()}
                       |> Async.RunSynchronously
                    ))

    app.Execute(argv)
