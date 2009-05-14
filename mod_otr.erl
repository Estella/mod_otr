%%%----------------------------------------------------------------------
%%% File    : mod_otr.erl
%%% Author  : Olivier Goffart  <ogoffar@kde.org>
%%% Purpose : Man In the Middle for OTR  
%%% Created : 23 Mar 2007
%%% Licence : GNU GPL v2 http://www.gnu.org/licenses/gpl.html
%%%----------------------------------------------------------------------

%% DESCRIPTION
%
% OTR (Off The Record messaging, http://www.cypherpunks.ca/otr/) is a protocol 
% for end to end encryption to be used with different instant messaging protocol
%
% This module, once loaded, will do the "man in the middle" at the server level
% In other word, it will decrypt messages, so the server administrator can read
% them.
%
% This module will emit hook that allow mod_logmnesia and mod_archive to log 
% encrypted message in plain text.
%
% I recomand to use this module  in combisaison with log_mnesia to see messages
% http://www.dp.uz.gov.ua/o.palij/mod_logmnesia/
%

%% HOW IT WORKS
%
% message are intercepted with the ejabberd's filter_packet hook, which is emit
% when a message is about to leave the jabber server to his destination (client 
% or other server). If this is an otr message this module read the message, 
% decrypt it, end re-encrypt it with his own public key. The plain text message
% is sent to other plugin using  user_send_packet and user_receive_packet hook 
% that are used by plugin such as mod_logmnesia
%

%% KNOWN BUGS
%
% - Only the version 2 of the OTR protocol is suported. (But it should be easy
%    to add support for version 1)
%
% - Fragmented messages are not supported. (but should be easy to support
%
% - Messages are logged twice,  first encrypted, then decrypted.  In order to
%   solve that I would need a hook that filter message _before_ they enter in
%   the server processing.
%
% - If user verify fingerprint, he will see they doesn't match.  But common
%   users generaly don't verify fingerprint
%

%% WHY THIS MODULE
%
% This module is only a proof of concept to show that end to end encryption 
% will never work for lambda user.  Lambda user don't care about encryption,
% so they will never verify their fingerprint.
% 
% TLS between XMPP entity is already a good security,  and users must trust
% the XMPP server they use
%
% I don't like automatic end to end encryption, because features like server
% archive, and server cache, will not work anymore.
%

%% INSTALL
%
%  You need libotr (tested with libotr-3.0.0) from  http://www.cypherpunks.ca/otr/#downloads
%  Example of compilation instruction (path must be fixed)
%
% gcc otr_drv.c -o otr_drv.so -fpic -shared -lerl_interface -lei  -lotr \
%   -L/usr/lib/erlang/lib/erl_interface-3.5.5.3/lib \
%   -I/usr/lib/erlang/lib/erl_interface-3.5.5.3/include -I/usr/lib/erlang/usr/include \
%   -L/opt/libotr/lib  -I/opt/libotr/include
% erlc -W  mod_otr.erl
%
% I suggest you to put the file in the ejabberd source directory if you have it.
% also, the mod_otr.beam must be paced with other module binaries, and the otr_drv.so
% with others .so files.

%% Changelog
% version 0.1 2007-03-29


%% uncommant this line if you want to see messages in the console.
% -define(otr_debug, true).


-module(mod_otr).
-author('ogoffart@kde.org').

-vsn('0.1').
-behaviour(gen_mod).

-export([start/2, init/2, stop/1, filter_packet/1 ]).

-include("jlib.hrl").

-define(OTR_PORT, otr_port).



-ifdef(otr_debug).
-define(MYDEBUG(Format, Args), io:format("D(~p:~p:~p) : "++Format++"~n",
                                       [calendar:local_time(),?MODULE,?LINE]++Args)).
-else.
-define(MYDEBUG(_F,_A),[]).
-endif.

-define(PROCNAME, ejabberd_mod_otr).


start(Host, Opts) ->
    register(gen_mod:get_module_proc(Host, ?PROCNAME),
                spawn(?MODULE, init, [Host, Opts])).

stop(Host) ->
    ?MYDEBUG("Stopping ~s", [?MODULE]),
    ejabberd_hooks:delete(filter_packet, global, ?MODULE, filter_packet, 10),
    ?MYDEBUG("Removed hooks", []),
    Proc = gen_mod:get_module_proc(Host, ?PROCNAME),
    Proc ! stop,
    {wait, Proc}.

init(Host, _Opts) ->
    case erl_ddll:load_driver(ejabberd:get_so_path(), otr_drv) of
        ok -> ok;
        {error, already_loaded} -> ok
    end,
    Port = open_port({spawn, otr_drv}, [{cd, "/tmp"}]),
    register(?OTR_PORT, Port),
    ejabberd_hooks:add(filter_packet, global, ?MODULE, filter_packet, 10),

    ?MYDEBUG("Added hooks", []),
    loop(Host , []).
    
    
loop(Host, OL ) ->
    receive
        stop ->
           ?MYDEBUG("Stopped", []),
           ok;
        _ ->
           ?MYDEBUG("Received unknown packet!", []),
           loop(Host, OL)
    end.


jid_to_str( J ) ->
    jlib:jid_to_string( jlib:jid_tolower( jlib:jid_remove_resource( J ) ) ).


filter_packet( { From, To , P } ) ->
  case parse_message_in( P ) of
    ignore -> { From , To, P } ;
    M -> 
        %?MYDEBUG("Message ~p" , [M] ),
        case  binary_to_term(port_control(?OTR_PORT, 0, term_to_binary( 
                    {  jid_to_str(From) , jid_to_str(To) ,  M}) )) of
            { ok , MsgOut } -> { From , To , lists:nth(1 , inject_body([P], MsgOut) ) };
            { ok , MsgOut , PlainText } ->  
                     ?MYDEBUG("We have the plain message : ~p" , [ PlainText ] )  ,
                     %send the plain message thought the hook as if we received it, so module such mod_logmnesia can log it
                     PlainMsg = lists:nth(1 , inject_body([P], "[mod_otr] " ++ PlainText )),
                     ejabberd_hooks:run(user_send_packet, From#jid.lserver, [From, To, PlainMsg ]),
                     ejabberd_hooks:run(user_receive_packet,To#jid.lserver, [To, From, To, PlainMsg ]),
                     { From , To , lists:nth(1,inject_body([P],MsgOut)) };
            _ -> { From , To , P }
        end
    end.
   
parse_message_in({xmlelement , "message" , _ , _ } = Packet) ->
    case xml:get_subtag(Packet, "body") of
         false ->  ignore;
         Body_xml ->   xml:get_tag_cdata(Body_xml)
    end;
parse_message_in(_) -> ignore.

inject_body( [ {xmlelement , Name , Attrs, Els} | Tail ] , New ) ->
    [ { xmlelement, Name, Attrs, 
        case Name of
                "body" ->
                    [{xmlcdata, New}];
                _ ->
                    inject_body( Els , New )
        end } | inject_body( Tail , New ) ] ;
inject_body( [ E | Tail ] , New ) -> 
    [ E |   inject_body( Tail , New )  ];
inject_body( [] , _ ) -> [].

