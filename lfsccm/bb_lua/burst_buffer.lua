--[[

Copyright (C) 2022 Nippon Telegraph and Telephone Corporation.

This software is released under the MIT License.
http://opensource.org/licenses/mit-license.php

]]--

socket = require("socket")

-- Configs
lua_script_name = "burst_buffer.lua"

-- Constants
RESPONSE_JOB_INFO = 2004
REQUEST_JOB_INFO_SINGLE = 2021
REQUEST_UPDATE_JOB = 3001
REQUEST_JOB_WILL_RUN = 4012
RESPONSE_JOB_WILL_RUN = 4013
RESPONSE_SLURM_RC = 8001
SLURM_21_08_PROTOCOL_VERSION = 9472
AUTH_PLUGIN_MUNGE = 101
SELECT_PLUGIN_CONS_TRES = 109
NO_VAL8 = 0xfe
NO_VAL16 = 0xfffe
NO_VAL = 0xfffffffe
NO_VAL64 = 0xfffffffffffffffe
SHOW_ALL = 0x0001
SHOW_DETAIL	= 0x0002

-- Private functions --

function _pack_header(msg_type, body_length)
    local header = string.pack(
        '>HHHHIHHH',
        SLURM_21_08_PROTOCOL_VERSION,  -- pack16(header->version, buffer);
        0,  -- pack16(header->flags, buffer);
        0,  -- pack16(header->msg_index, buffer);
        msg_type,  -- pack16(header->msg_type, buffer);
        body_length,  -- pack32(header->body_length, buffer);
        0,  -- pack16(header->forward.cnt, buffer);
        0,  -- pack16(header->ret_cnt, buffer);
        0  -- pack16(addr->ss_family, buffer);
    )
    return header
end

function _unpack_header(resp, pos)
    local _, _, _, msg_type, _, _, _, _, pos = string.unpack('>HHHHIHHH', resp, pos)
    return msg_type, pos
end

function _pack_job_ready_msg(job_id, show_flag)
    return string.pack('>IH', job_id, show_flag)
end

function _pack_job_desc_msg(job_id, req_nodes)
    local data = string.pack(
        '>Is4s4s4Hs4HIHs4LLIs4s4 s4Is4s4HLIB III s4Is4s4s4s4IIs4s4 s4BBs4I'..
        's4s4s4s4s4s4s4 s4s4s4s4s4 HHHHHHHHHH HHHs4s4 IIIIIIHHHHHII Hs4Hs4LLL'..
        's4Hs4s4HHHHs4II IHLIs4Hs4s4H s4s4s4s4s4s4s4s4B',
        NO_VAL,  -- pack32(job_desc_ptr->site_factor, buffer);
        '',  -- packstr(job_desc_ptr->batch_features, buffer);
        '',  -- packstr(job_desc_ptr->cluster_features, buffer);
        '',  -- packstr(job_desc_ptr->clusters, buffer);
        NO_VAL16,  -- pack16(job_desc_ptr->contiguous, buffer);
        '',  -- packstr(job_desc_ptr->container, buffer);
        NO_VAL16,  -- pack16(job_desc_ptr->core_spec, buffer);
        NO_VAL,  -- pack32(job_desc_ptr->task_dist, buffer);
        NO_VAL16,  -- pack16(job_desc_ptr->kill_on_node_fail, buffer);
        '',  -- packstr(job_desc_ptr->features, buffer);
        0,  -- pack64(job_desc_ptr->fed_siblings_active, buffer);
        0,  -- pack64(job_desc_ptr->fed_siblings_viable, buffer);
        job_id,  -- pack32(job_desc_ptr->job_id, buffer);
        '',  -- packstr(job_desc_ptr->job_id_str, buffer);
        '',  -- packstr(job_desc_ptr->name, buffer);

        '',  -- packstr(job_desc_ptr->alloc_node, buffer);
        NO_VAL,  -- pack32(job_desc_ptr->alloc_sid, buffer);
        '',  -- packstr(job_desc_ptr->array_inx, buffer);
        '',  -- packstr(job_desc_ptr->burst_buffer, buffer);
        NO_VAL16,  -- pack16(job_desc_ptr->pn_min_cpus, buffer);
        NO_VAL64,  -- pack64(job_desc_ptr->pn_min_memory, buffer);
        NO_VAL,  -- pack32(job_desc_ptr->pn_min_tmp_disk, buffer);
        0,  -- pack8(job_desc_ptr->power_flags, buffer);

        NO_VAL,  -- pack32(job_desc_ptr->cpu_freq_min, buffer);
        NO_VAL,  -- pack32(job_desc_ptr->cpu_freq_max, buffer);
        NO_VAL,  -- pack32(job_desc_ptr->cpu_freq_gov, buffer);

        '',  -- packstr(job_desc_ptr->partition, buffer);
        NO_VAL,  -- pack32(job_desc_ptr->priority, buffer);
        '',  -- packstr(job_desc_ptr->dependency, buffer);
        '',  -- packstr(job_desc_ptr->account, buffer);
        '',  -- packstr(job_desc_ptr->admin_comment, buffer);
        '',  -- packstr(job_desc_ptr->comment, buffer);
        NO_VAL,  -- pack32(job_desc_ptr->nice, buffer);
        0,  -- pack32(job_desc_ptr->profile, buffer);
        '',  -- packstr(job_desc_ptr->qos, buffer);
        '',  -- packstr(job_desc_ptr->mcs_label, buffer);

        '',  -- packstr(job_desc_ptr->origin_cluster, buffer);
        0,  -- pack8(job_desc_ptr->open_mode,   buffer);
        NO_VAL8,  -- pack8(job_desc_ptr->overcommit,  buffer);
        '',  -- packstr(job_desc_ptr->acctg_freq, buffer);
        NO_VAL,  -- pack32(job_desc_ptr->num_tasks,  buffer);

        '',  -- packstr(job_desc_ptr->req_context, buffer);
        req_nodes.."\0",  -- packstr(job_desc_ptr->req_nodes, buffer);
        '',  -- packstr(job_desc_ptr->exc_nodes, buffer);
        '',  -- packstr_array(job_desc_ptr->environment,
            -- job_desc_ptr->env_size, buffer);
        '',  -- packstr_array(job_desc_ptr->spank_job_env,
            -- job_desc_ptr->spank_job_env_size, buffer);
        '',  -- packstr(job_desc_ptr->script, buffer);
        '',  -- packstr_array(job_desc_ptr->argv, job_desc_ptr->argc, buffer);

        '',  -- packstr(job_desc_ptr->std_err, buffer);
        '',  -- packstr(job_desc_ptr->std_in, buffer);
        '',  -- packstr(job_desc_ptr->std_out, buffer);
        '',  -- packstr(job_desc_ptr->submit_line, buffer);
        '',  -- packstr(job_desc_ptr->work_dir, buffer);

        0,  -- pack16(job_desc_ptr->immediate, buffer);
        NO_VAL16,  -- pack16(job_desc_ptr->reboot, buffer);
        NO_VAL16,  -- pack16(job_desc_ptr->requeue, buffer);
        NO_VAL16,  -- pack16(job_desc_ptr->shared, buffer);
        NO_VAL16,  -- pack16(job_desc_ptr->cpus_per_task, buffer);
        NO_VAL16,  -- pack16(job_desc_ptr->ntasks_per_node, buffer);
        0,  -- pack16(job_desc_ptr->ntasks_per_board, buffer);
        NO_VAL16,  -- pack16(job_desc_ptr->ntasks_per_socket, buffer);
        NO_VAL16,  -- pack16(job_desc_ptr->ntasks_per_core, buffer);
        NO_VAL16,  -- pack16(job_desc_ptr->ntasks_per_tres, buffer);

        NO_VAL16,  -- pack16(job_desc_ptr->plane_size, buffer);
        NO_VAL16,  -- pack16(job_desc_ptr->cpu_bind_type, buffer);
        NO_VAL16,  -- pack16(job_desc_ptr->mem_bind_type, buffer);
        '',  -- packstr(job_desc_ptr->cpu_bind, buffer);
        '',  -- packstr(job_desc_ptr->mem_bind, buffer);

        NO_VAL,  -- pack32(job_desc_ptr->time_limit, buffer);
        NO_VAL,  -- pack32(job_desc_ptr->time_min, buffer);
        NO_VAL,  -- pack32(job_desc_ptr->min_cpus, buffer);
        NO_VAL,  -- pack32(job_desc_ptr->max_cpus, buffer);
        NO_VAL,  -- pack32(job_desc_ptr->min_nodes, buffer);
        NO_VAL,  -- pack32(job_desc_ptr->max_nodes, buffer);
        0,  -- pack16(job_desc_ptr->boards_per_node, buffer);
        0,  -- pack16(job_desc_ptr->sockets_per_board, buffer);
        NO_VAL16,  -- pack16(job_desc_ptr->sockets_per_node, buffer);
        NO_VAL16,  -- pack16(job_desc_ptr->cores_per_socket, buffer);
        NO_VAL16,  -- pack16(job_desc_ptr->threads_per_core, buffer);
        NO_VAL,  -- pack32(job_desc_ptr->user_id, buffer);
        NO_VAL,  -- pack32(job_desc_ptr->group_id, buffer);

        0,  -- pack16(job_desc_ptr->alloc_resp_port, buffer);
        '',  -- packstr(job_desc_ptr->resp_host, buffer);
        0,  -- pack16(job_desc_ptr->other_port, buffer);
        '',  -- packstr(job_desc_ptr->network, buffer);
        0,  -- pack_time(job_desc_ptr->begin_time, buffer);
        0,  -- pack_time(job_desc_ptr->end_time, buffer);
        0,  -- pack_time(job_desc_ptr->deadline, buffer);

        '',  -- packstr(job_desc_ptr->licenses, buffer);
        NO_VAL16,  -- pack16(job_desc_ptr->mail_type, buffer);
        '',  -- packstr(job_desc_ptr->mail_user, buffer);
        '',  -- packstr(job_desc_ptr->reservation, buffer);
        0,  -- pack16(job_desc_ptr->restart_cnt, buffer);
        0,  -- pack16(job_desc_ptr->warn_flags, buffer);
        0,  -- pack16(job_desc_ptr->warn_signal, buffer);
        0,  -- pack16(job_desc_ptr->warn_time, buffer);
        '',  -- packstr(job_desc_ptr->wckey, buffer);
        NO_VAL,  -- pack32(job_desc_ptr->req_switch, buffer);
        NO_VAL,  -- pack32(job_desc_ptr->wait4switch, buffer);

        SELECT_PLUGIN_CONS_TRES,  -- pack32(*(ops[plugin_id].plugin_id), buffer);
        NO_VAL16,  -- pack16(job_desc_ptr->wait_all_nodes, buffer);
        NO_VAL64,  -- pack64(job_desc_ptr->bitflags, buffer);
        NO_VAL,  -- pack32(job_desc_ptr->delay_boot, buffer);
        '',  -- packstr(job_desc_ptr->extra, buffer);
        0,  -- pack16(job_desc_ptr->x11, buffer);
        '',  -- packstr(job_desc_ptr->x11_magic_cookie, buffer);
        '',  -- packstr(job_desc_ptr->x11_target, buffer);
        0,  -- pack16(job_desc_ptr->x11_target_port, buffer);

        '',  -- packstr(job_desc_ptr->cpus_per_tres, buffer);
        '',  -- packstr(job_desc_ptr->mem_per_tres, buffer);
        '',  -- packstr(job_desc_ptr->tres_bind, buffer);
        '',  -- packstr(job_desc_ptr->tres_freq, buffer);
        '',  -- packstr(job_desc_ptr->tres_per_job, buffer);
        '',  -- packstr(job_desc_ptr->tres_per_node, buffer);
        '',  -- packstr(job_desc_ptr->tres_per_socket, buffer);
        '',  -- packstr(job_desc_ptr->tres_per_task, buffer);
        0  -- pack_cron_entry(job_desc_ptr->crontab_entry, protocol_version, buffer);
    )
    return data
end

function _unpack_array(pack, pos, size_fmt)
    unpack_tbl = {}
    local cnt, pos = string.unpack('>I', pack, pos)
    for i=1, cnt, 1 do
        local data_tbl = {string.unpack('>'..size_fmt, pack, pos)}
        table.insert(unpack_tbl, data_tbl[1])
        pos = data_tbl[#data_tbl]
    end
    return unpack_tbl, pos
end

function _unpack_bit_str_hex(pack, pos)
    local size, pos = string.unpack('>I', pack, pos)
    if size ~= NO_VAL then
        _, pos = string.unpack('>s4', pack, pos)
    end
    return _, pos
end

function _unpack_req_nodes(resp, pos)
    local record_count, _, _, pos = string.unpack('>ILL', resp, pos)
    if record_count ~= 1 then
        return nil
    end
    local tbl = {string.unpack(
        '>IIs4I Is4IIIIIs4II IHHBBHHL III I'..
        'LLLLLLLLLLIds4s4s4s4s4s4Is4s4s4s4s4s4s4s4s4Ls4s4s4s4', resp, pos)}
    pos = tbl[#tbl]
    local _, _, _, empty, pos = string.unpack('>IIs4I', resp, pos)
    if empty ~= NO_VAL then
        -- unpack_job_resources
        tbl = {string.unpack('>IIs4BHH', resp, pos)}
        pos = tbl[#tbl]
        _, pos = _unpack_array(resp, pos, 'I')
        _, pos = _unpack_array(resp, pos, 'H')
        _, pos = _unpack_array(resp, pos, 'H')
        _, pos = _unpack_array(resp, pos, 'H')
        _, pos = _unpack_array(resp, pos, 'L')
        _, pos = _unpack_array(resp, pos, 'L')
        _, pos = _unpack_array(resp, pos, 'H')
        _, pos = _unpack_array(resp, pos, 'I')
        _, pos = _unpack_bit_str_hex(resp, pos)
        _, pos = _unpack_bit_str_hex(resp, pos)
    end
    _, pos = _unpack_array(resp, pos, 's4')
    tbl = {string.unpack('>s4s4s4IIs4', resp, pos)}
    pos = tbl[#tbl]
    _, pos = _unpack_bit_str_hex(resp, pos)  -- job->node_inx
    tbl = {string.unpack('>Is4s4s4s4s4 IIIIHHHI HIII s4 HHHH LI', resp, pos)}
    pos = tbl[#tbl]
    local req_nodes, pos = string.unpack('>s4', resp, pos)
    return req_nodes
end

function _unpack_will_run_response_msg(resp, pos)
    local job_id, _, will_run_node = string.unpack('>Is4s4', resp, pos)
    return will_run_node
end

function _unpack_return_code_msg(resp, pos)
    local rc = string.unpack('>I', resp, pos)
    return rc
end

function _pack_auth()
    local auth = string.pack(
        '>Is4',
        AUTH_PLUGIN_MUNGE,  --pack32(*ops[wrap->index].plugin_id, buf);
        _munge_encode().."\0"  --packstr(cred->m_str, buf);
    )
    return auth
end

function _unpack_auth(resp, pos)
    local plugin_id, cred, pos = string.unpack('>Is4', resp, pos)
    return pos
end

function _munge_encode()
    local handle = io.popen('munge -n', 'r')
    local cred = handle:read("*all")
    handle:close()
    return string.gsub(cred, "\n", "")
end

function _split(str, sep)
    if sep == nil then return {} end
    local t = {}
    local i = 1
    for s in string.gmatch(str, "([^"..sep.."]+)") do
      t[i] = s
      i = i + 1
    end
    return t
end

function _table_len(table)
    local n = 0
    for _ in pairs(table) do
        n = n + 1
    end
    return n
end

function _convert_long2short(val, valid_tbl)
    val = string.lower(val)
    for k, v in pairs(valid_tbl) do
        if val == k or val == v then
            return k
        end
    end
    return nil
end

function _parse_job_script(job_script)
    local err = nil
    local valid_opts = {
        p = "path",
        m = "mode",
        r = "recursive"
    }
    local valid_modes = {
        ro = "readonly",
        rw = "readwrite"
    }

    -- Read jobscript
    local pcc_lines = {}
    local fp = io.open(job_script, "r")
    for line in fp:lines() do
        if line:find("^#PCC") then
            table.insert(pcc_lines, line)
        end
    end
    io.close(fp)

    -- Read burst_buffer.conf
    local bb_conf, err = _read_bb_conf()
    if err then
        err = string.format("Read burst_buffer.conf failed: %s", err)
        return nil, err
    end
    local directive = "#"..bb_conf["Directive"]

    -- Parse jobscript
    local files = {}
    for _, line in ipairs(pcc_lines) do
        local args = _split(line, " ")
        local paths = {}
        local mode = nil
        local recursive = ""
        local value_type = nil

        for _, arg in ipairs(args) do
            if not arg then
                goto continue
            end

            if arg == directive then
                goto continue
            end

            local opt = nil
            local short_opt = nil
            local value = nil
            if not value_type then
                if not arg:find("^-") then
                    err = string.format("invalid option: %s", arg)
                    break
                end

                -- Skip "-" and "--"
                local opt_pos = 2
                if arg:sub(2,2) == "-" then
                    opt_pos = opt_pos + 1
                end

                local with_val = arg:find("=", 1, true)
                if with_val then
                    opt = arg:sub(opt_pos, with_val-1)
                    value = arg:sub(with_val+1)
                else
                    opt = arg:sub(opt_pos)
                    value = nil
                end

                short_opt = _convert_long2short(opt, valid_opts)
                if not short_opt then
                    err = string.format("invalid option: %s", arg)
                    break
                end

                if short_opt == "r" then
                    recursive = "r"
                end
            else
                short_opt = value_type
                value = arg
                value_type = nil
            end

            if value then
                if short_opt == "p" then
                    table.insert(paths, value)
                elseif short_opt == "m" then
                    if mode then
                        err = string.format("Duplicate mode option: %s", arg)
                        break
                    end
                    local short_mode = _convert_long2short(value, valid_modes)
                    if not short_mode then
                        err = string.format("Invalid mode option: %s", arg)
                        break
                    end
                    mode = short_mode
                end
            else
                if short_opt == "p" then
                    value_type = short_opt
                elseif short_opt == "m" then
                    if mode then
                        err = string.format("Duplicate mode option: %s", arg)
                        break
                    end
                    value_type = short_opt
                end
            end
            ::continue::
        end

        if err then
            break
        end

        if not mode then
            mode = "rw"
        end

        if #paths ~= 0 then
            table.insert(files, string.format("%s:%s:%s",
                table.concat(paths, ","), mode, recursive))
        end
    end

    if not err and #files == 0 then
        err = string.format("No path option")
    end
    return files, err
end

function _send_recv_controller_msg(msg_type, body)
    -- send request
    local header = _pack_header(msg_type, #body)
    local auth = _pack_auth()
    local req_size = string.pack('>I', #header + #auth + #body)

    local slurm_conf, err = _read_slurm_conf()
    if err then
        slurm.log_error("%s: _send_recv_controller_msg(). %s", lua_script_name, err)
        return nil
    end
    local slurmctld_ip = socket.dns.toip(slurm_conf["SlurmctldHost"])
    local slurmctld_port = slurm_conf["SlurmctldPort"]

    local client = socket.connect(slurmctld_ip, slurmctld_port)
    client:send(req_size..header..auth..body)

    -- receive response
    local resp_size = string.unpack('>I', client:receive(4))
    local resp = client:receive(resp_size)
    client:close()
    return resp
end

function _unpack_response(resp)
    local data, err = nil, nil
    if not resp then
        err = string.format("%s: _unpack_response(). No RPC response", lua_script_name)
        return nil, err
    end

    local msg_type, pos = _unpack_header(resp, 1)
    local pos = _unpack_auth(resp, pos)
    if msg_type == RESPONSE_JOB_WILL_RUN then
        data = string.gsub(_unpack_will_run_response_msg(resp, pos), "\0", "")
    elseif msg_type == RESPONSE_JOB_INFO then
        data = string.gsub(_unpack_req_nodes(resp, pos), "\0", "")
    elseif msg_type == RESPONSE_SLURM_RC then
        rc = _unpack_return_code_msg(resp, pos)
        if rc ~= 0 then
            err = string.format("%s: _unpack_response(). Unexpected return code received (rc: %d)",
                lua_script_name, rc)
        end
    else
        err = string.format("%s: _unpack_response(). Unexpected message received (msg_type: %d)",
            lua_script_name, msg_type)
    end
    return data, err
end

function _get_will_run_node(job_id)
    local body = _pack_job_desc_msg(job_id, '')
    local resp = _send_recv_controller_msg(REQUEST_JOB_WILL_RUN, body)
    return _unpack_response(resp)
end

function _update_req_node(job_id, req_node)
    local body = _pack_job_desc_msg(job_id, req_node)
    local resp = _send_recv_controller_msg(REQUEST_UPDATE_JOB, body)
    return _unpack_response(resp)
end

function _get_req_node(job_id)
    local body = _pack_job_ready_msg(job_id, SHOW_ALL|SHOW_DETAIL)
    local resp = _send_recv_controller_msg(REQUEST_JOB_INFO_SINGLE, body)
    return _unpack_response(resp)
end

function _expand_nodename(nodes)
    local node_sep = {}
    local bracket_node = ""
    local in_bracket, end_bracket = nil, nil
    for _, part in ipairs(_split(nodes, ",")) do
        if not in_bracket then
            in_bracket = part:find("%[")
        end
        end_bracket = part:find("%]")
        if in_bracket and end_bracket then
            bracket_node = bracket_node..part
            table.insert(node_sep, bracket_node)
            in_bracket, end_bracket = nil, nil
            bracket_node = ""
        elseif in_bracket and not end_bracket then
            bracket_node = bracket_node..part..","
        elseif not in_bracket and end_bracket then
            return nil, "err"
        elseif not in_bracket and not end_bracket then
            table.insert(node_sep, part)
        end
    end

    local node_table = {}
    for _, node in ipairs(node_sep) do
        local pos_start = node:find("%[")
        local pos_end = node:find("%]")
        if not (pos_start and pos_end) then
            table.insert(node_table, node)
            goto continue
        end

        local base = node:sub(1, pos_start-1)
        local numbers = node:sub(pos_start+1, pos_end-1)
        local num_table = {}
        for _, num in ipairs(_split(numbers, ",")) do
            local pos_sep = num:find("-")
            if pos_sep then
                local first = tonumber(num:sub(1, pos_sep-1))
                local last = tonumber(num:sub(pos_sep+1))
                if not (first and last) then
                    return {}, "err"
                end
                for count=first, last do
                    table.insert(num_table, count)
                end
            else
                local count = tonumber(num)
                if not num then
                    return {}, "err"
                end
                table.insert(num_table, count)
            end
        end

        for _, num in ipairs(num_table) do
            table.insert(node_table, base..num)
        end
        ::continue::
    end
    if #node_table == 0 then
        return {}, "err"
    end
    return node_table, nil
end

function _cache_pcc(req_nodes, files)
    -- Get rwid, roid
    local err = nil
    local node_tbl, rwid_tbl, roid_tbl = {}, {}, {}
    local pcc_conf, err = _read_pcc_conf()
    if err then
        return err
    end

    node_table, err = _expand_nodename(req_nodes)
    if err then
        return err
    end
    for _, node in ipairs(node_table) do
        local found = false
        for _, config in ipairs(pcc_conf) do
            if node == config["node"] then
                table.insert(node_tbl, config["node"])
                table.insert(rwid_tbl, config["rwid"])
                table.insert(roid_tbl, config["roid"])
                found = true
                break
            end
        end
        if not found then
            err = string.format("Target node: %s has no PCC", node)
            break
        end
    end
    if err then
        return err
    end

    -- Check SSH connection
    local cmd = {}
    table.insert(cmd, "lfsccm")
    table.insert(cmd, "check-ssh-connection")
    table.insert(cmd, "--nodes="..table.concat(node_tbl, ","))
    slurm.log_info("%s: _cache_pcc(). cmd: %s", lua_script_name, table.concat(cmd, " "))
    local _, _, rc = os.execute(table.concat(cmd, " "))
    if rc ~= 0 then
        err = "SSH connection failed"
        return err
    end

    -- Cache files
    local cmd = {}
    table.insert(cmd, "lfsccm")
    table.insert(cmd, "attach")
    table.insert(cmd, "--nodes="..table.concat(node_tbl, ","))
    table.insert(cmd, "--rw-ids="..table.concat(rwid_tbl, ","))
    table.insert(cmd, "--ro-ids="..table.concat(roid_tbl, ","))
    for _, file in ipairs(files) do
        table.insert(cmd, "--files="..file)
    end

    slurm.log_info("%s: _cache_pcc(). cmd: %s", lua_script_name, table.concat(cmd, " "))

    local handle = io.popen(table.concat(cmd, " ").." 2>&1")
    local stdout = handle:read("*all")
    handle:close()
    slurm.log_info("%s: _cache_pcc(). stdout: %s", lua_script_name, stdout)
    return err
end

function _read_conf(conf_file)
    local path = debug.getinfo(1).source
    local conf_dir = path:sub(2, path:len() - lua_script_name:len())

    local lines = {}
    local fp = io.open(conf_dir..conf_file, "r")
    if not fp then
        return nil, string.format("'%s' not found", conf_dir..conf_file)
    end
    for line in fp:lines() do
        if not line:match("^%s*#") then
            table.insert(lines, line)
        end
    end
    io.close(fp)
    return lines, nil
end

function _read_slurm_conf()
    local err = nil
    local params = {
        SlurmctldHost = true,
        SlurmctldPort = true
    }

    local lines, err = _read_conf("slurm.conf")
    if err then
        return nil, err
    end

    local slurm_conf = {}
    for _, line in ipairs(lines) do
        k, v = line:match("(%S*)=(%S*)")
        if params[k] then
            slurm_conf[k] = v
        end
    end

    if _table_len(slurm_conf) ~= _table_len(params) then
        err = "slurm.conf lacks required parameters"
    end
    return slurm_conf, err
end

function _check_slurm_conf()
    local _, err = _read_slurm_conf()
    return err
end

function _read_bb_conf()
    local err = nil
    local lines, err = _read_conf("burst_buffer.conf")
    if err then
        return nil, err
    end

    local bb_conf = {}
    for _, line in ipairs(lines) do
        k, v = line:match("(%S*)=(%S*)")
        if k == "Directive" then
            bb_conf[k] = v
        end
    end
    if _table_len(bb_conf) ~= 1 then
        err = "burst_buffer.conf lacks required parameters"
    end
    return bb_conf, err
end

function _read_pcc_conf()
    local err = nil
    local lines, err = _read_conf("lfsccm.conf")
    if err then
        return nil, err
    end

    local pcc_configs = {}
    for _, line in ipairs(lines) do
        local args = _split(line, " ")
        local nodename, roid, rwid = nil, nil, nil
        for _, arg in ipairs(args) do
            if arg:find("NodeName=") then
                if nodename then
                    err = string.format("pcc.conf: Duplicate NodeName at '%s'", line)
                end
                nodename = arg:sub(10)
            elseif arg:find("roid=") then
                if roid then
                    err = string.format("pcc.conf: Duplicate roid at '%s'", line)
                end
                roid = arg:sub(6)
            elseif arg:find("rwid=") then
                if rwid then
                    err = string.format("pcc.conf: Duplicate rwid at '%s'", line)
                end
                rwid = arg:sub(6)
            else
                err = string.format("pcc.conf: Unexpected option at '%s'", line)
            end
            if err then
                break
            end
        end

        if err then
            break
        end

        table.insert(pcc_configs, {
            node=nodename,
            roid=math.tointeger(roid),
            rwid=math.tointeger(rwid)
        })
    end

    if not err and #pcc_configs == 0 then
        err = "pcc.conf has no data"
    end
    return pcc_configs, err
end

function _check_pcc_conf()
    local err = nil
    local pcc_configs, err = _read_pcc_conf()
    if err then
        return err
    end

    for _, pcc in ipairs(pcc_configs) do
        if not pcc.node or pcc.node == "" then
            err = "pcc.conf: Invalid node"
        end
        if not pcc.roid or type(pcc.roid) ~= "number" then
            err = string.format("pcc.conf: node=%s Invalied roid", pcc.node)
        end
        if not pcc.rwid or type(pcc.rwid) ~= "number" then
            err = string.format("pcc.conf: node=%s Invalied rwid", pcc.node)
        end
    end
    return err
end

function _check_ro_available(files)
    local err = nil
    local use_ro = false
    for _, file in ipairs(files) do
        local paths, mode = table.unpack(_split(file, ":"))
        local path_tbl = _split(paths, ",")
        for _, path in ipairs(path_tbl) do
            if mode == "ro" then
                use_ro = true
            end
        end
    end

    if not use_ro then
        return nil
    end

    local cmd = {}
    table.insert(cmd, "lfsccm")
    table.insert(cmd, "check-ro-available")
    slurm.log_info("%s: _check_ro_available(). cmd: %s", lua_script_name, table.concat(cmd, " "))

    local handle = io.popen(table.concat(cmd, " ").." 2>&1")
    local stdout = handle:read("*all")
    local _, _, rc = handle:close()

    if rc ~= 0 then
        slurm.log_error("%s: _check_ro_available(). cmd: %s, rc: %d, stdout: %s",
            lua_script_name, table.concat(cmd, " "), rc, stdout)

        if stdout == "" then
            err = string.format("Unexpected errors occurred")
            return err
        end

        _, _, out = string.find(stdout, "(PCC RO mode requires Lustre .+)")
        if out then
            return out
        end

        err = string.format("Unexpected errors occurred. Please see the slurmctld.log")
        return err
    end

    return err
end

function _check_duplicates(files)
    local err = nil
    local ro_paths, rw_paths = {}, {}
    for _, file in ipairs(files) do
        local paths, mode = table.unpack(_split(file, ":"))
        local path_tbl = _split(paths, ",")
        for _, path in ipairs(path_tbl) do
            if mode == "ro" then
                table.insert(ro_paths, path)
            elseif mode == "rw" then
                table.insert(rw_paths, path)
            end
        end
    end

    local dup_files = {}
    for _, ro_path in ipairs(ro_paths) do
        for _, rw_path in ipairs(rw_paths) do
            if ro_path == rw_path then
                table.insert(dup_files, ro_path)
            end
        end
    end
    if #dup_files ~= 0 then
        err = string.format("Duplicate files in rw and ro: %s",
            table.concat(dup_files, ','))
    end
    return err
end

function _check_recursive(files)
    local err = nil
    for _, file in ipairs(files) do
        local paths, mode, recursive = table.unpack(_split(file, ":"))
        if recursive == "r" then
            if not string.find(paths, "*") then
                err = string.format(
                        "recursive option is given, but wildcard(*) is not found: %s",
                        paths)
                return err
            end
        end
    end
    return err
end

function _check_files(files)
    local err = nil
    local cmd = {}
    table.insert(cmd, "lfsccm")
    table.insert(cmd, "check-files")
    for _, file in ipairs(files) do
        table.insert(cmd, "--files="..file)
    end
    slurm.log_info("%s: _check_files(). cmd: %s", lua_script_name, table.concat(cmd, " "))

    local handle = io.popen(table.concat(cmd, " ").." 2>&1")
    local stdout = handle:read("*all")
    local _, _, rc = handle:close()

    if rc ~= 0 then
        slurm.log_error("%s: _check_files(). cmd: %s, rc: %d, stdout: %s",
            lua_script_name, table.concat(cmd, " "), rc, stdout)

        if stdout == "" then
            err = string.format("Unexpected errors occurred")
            return err
        end

        local nofiles = {}
        for nofile in string.gmatch(stdout, "\'(.+)\': No such file or directory") do
            table.insert(nofiles, nofile)
        end
        if _table_len(nofiles) ~= 0 then
            err = string.format(
                "Files does not exist in Lustre: %s", table.concat(nofiles, ", "))
            return err
        end

        err = string.format("Unexpected errors occurred. Please see the slurmctld.log")
    end
    return err
end

-- Public functions --

--[[
--slurm_bb_job_process
--
--WARNING: This function is called synchronously from slurmctld and must
--return quickly.
--
--This function is called on job submission.
--This example reads, logs, and returns the job script.
--If this function returns an error, the job is rejected and the second return
--value (if given) is printed where salloc, sbatch, or srun was called.
--]]
function slurm_bb_job_process(job_script)
    slurm.log_info("%s: slurm_bb_job_process(). job script:%s", lua_script_name, job_script)

    local err = _check_slurm_conf()
    if err then
        return slurm.ERROR, err
    end

    local err = _check_pcc_conf()
    if err then
        return slurm.ERROR, err
    end

    local files, err = _parse_job_script(job_script)
    if err then
        return slurm.ERROR, err
    end

    local err = _check_ro_available(files)
    if err then
        return slurm.ERROR, err
    end

    local err = _check_duplicates(files)
    if err then
        return slurm.ERROR, err
    end

    local err = _check_recursive(files)
    if err then
        return slurm.ERROR, err
    end

    local err = _check_files(files)
    if err then
        return slurm.ERROR, err
    end

    return slurm.SUCCESS
end

--[[
--slurm_bb_pools
--
--WARNING: This function is called from slurmctld and must return quickly.
--
--This function is called on slurmctld startup, and then periodically while
--slurmctld is running.
--
--You may specify "pools" of resources here. If you specify pools, a job may
--request a specific pool and the amount it wants from the pool. Slurm will
--subtract the job's usage from the pool at slurm_bb_data_in and Slurm will
--add the job's usage of those resources back to the pool after
--slurm_bb_teardown.
--A job may choose not to specify a pool even you pools are provided.
--If pools are not returned here, Slurm does not track burst buffer resources
--used by jobs.
--
--If pools are desired, they must be returned as the second return value
--of this function. It must be a single JSON string representing the pools.
--]]
function slurm_bb_pools()
    return slurm.SUCCESS
end

--[[
--slurm_bb_setup
--
--This function is called asynchronously and is not required to return quickly.
--This function is called while the job is pending.
--]]
function slurm_bb_setup(job_id, uid, gid, pool, bb_size, job_script)
    slurm.log_info("%s: slurm_bb_setup(). job id:%s, uid: %s, gid:%s, pool:%s, size:%s, job script:%s",
            lua_script_name, job_id, uid, gid, pool, bb_size, job_script)

    local will_run_node, err = _get_will_run_node(job_id)
    if err then
        slurm.log_error("%s: slurm_bb_setup(). _get_will_run_node failed (err: %s)",
        lua_script_name, err)
        return slurm.SUCCESS
    end
    slurm.log_info("%s: slurm_bb_setup(). will_run_node: %s", lua_script_name, will_run_node)

    local _, err = _update_req_node(job_id, will_run_node)
    if err then
        slurm.log_error("%s: slurm_bb_setup(). _update_req_node failed (err: %s)",
            lua_script_name, err)
        return slurm.SUCCESS
    end

    return slurm.SUCCESS
end

--[[
--slurm_bb_data_in
--
--This function is called asynchronously and is not required to return quickly.
--This function is called immediately after slurm_bb_setup while the job is
--pending.
--]]
function slurm_bb_data_in(job_id, job_script)
    slurm.log_info("%s: slurm_bb_data_in(). job id:%s, job script:%s",
            lua_script_name, job_id, job_script)

    -- Get target files from jobscript
    local files, err = _parse_job_script(job_script)
    if err then
        slurm.log_error("%s: slurm_bb_data_in(). _parse_job_script failed (err: %s)",
            lua_script_name, err)
        return slurm.SUCCESS
    end
    slurm.log_info("%s: slurm_bb_data_in(). _parse_job_script: files: %s",
        lua_script_name, table.concat(files, ','))

    -- Get req_nodes
    local req_nodes, err = _get_req_node(job_id)
    if err then
        slurm.log_error("%s: slurm_bb_data_in(). _get_req_node failed (err: %s)",
            lua_script_name, err)
            return slurm.SUCCESS
    end
    slurm.log_info("%s: slurm_bb_data_in(). _get_req_node: req_nodes: %s",
        lua_script_name, req_nodes)

    -- Run pcc command
    local err = _cache_pcc(req_nodes, files)
    if err then
        slurm.log_error("%s: slurm_bb_data_in(). _cache_pcc failed (err: %s)",
            lua_script_name, err)
        return slurm.SUCCESS
    end

    return slurm.SUCCESS
end

--[[
--slurm_bb_real_size
--
--This function is called asynchronously and is not required to return quickly.
--This function is called immediately after slurm_bb_data_in while the job is
--pending.
--
--This function is only called if pools are specified and the job requested a
--pool. This function may return a number (surrounded by quotes to make it a
--string) as the second return value. If it does, the job's usage of the pool
--will be changed to this number. A commented out example is given.
--]]
function slurm_bb_real_size(job_id)
    return slurm.SUCCESS
end

--[[
--slurm_bb_paths
--
--WARNING: This function is called synchronously from slurmctld and must
--return quickly.
--This function is called after the job is scheduled but before the
--job starts running when the job is in a "running + configuring" state.
--
--The file specfied by path_file is an empty file. If environment variables are
--written to path_file, these environment variables are added to the job's
--environment. A commented out example is given.
--]]
function slurm_bb_paths(job_id, job_script, path_file)
    return slurm.SUCCESS
end

--[[
--slurm_bb_pre_run
--
--This function is called asynchronously and is not required to return quickly.
--This function is called after the job is scheduled but before the
--job starts running when the job is in a "running + configuring" state.
--]]
function slurm_bb_pre_run(job_id, job_script)
    return slurm.SUCCESS
end

--[[
--slurm_bb_post_run
--
--This function is called asynchronously and is not required to return quickly.
--This function is called after the job finishes. The job is in a "stage out"
--state.
--]]
function slurm_bb_post_run(job_id, job_script)
    return slurm.SUCCESS
end

--[[
--slurm_bb_data_out
--
--This function is called asynchronously and is not required to return quickly.
--This function is called after the job finishes immediately after
--slurm_bb_post_run. The job is in a "stage out" state.
--]]
function slurm_bb_data_out(job_id, job_script)
    return slurm.SUCCESS
end

--[[
--slurm_bb_job_teardown
--
--This function is called asynchronously and is not required to return quickly.
--This function is normally called after the job completes (or is cancelled).
--]]
function slurm_bb_job_teardown(job_id, job_script, hurry)
    return slurm.SUCCESS
end

--[[
--slurm_bb_get_status
--
--This function is called asynchronously and is not required to return quickly.
--
--This function is called when "scontrol show bbstat" is run. It recieves a
--variable number of arguments - whatever arguments are after "bbstat".
--For example:
--
--  scontrol show bbstat foo bar
--
--This command will pass 2 arguments to this functions: "foo" and "bar".
--
--If this function returns slurm.SUCCESS, then this function's second return
--value will be printed where the scontrol command was run. If this function
--returns slurm.ERROR, then this function's second return value is ignored and
--an error message will be printed instead.
--
--The example in this function simply prints the arguments that were given.
--]]
function slurm_bb_get_status(...)
    return slurm.SUCCESS, "Status return message\n"
end
