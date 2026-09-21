package com.honeygrid.honeygrid.controller;
import com.honeygrid.honeygrid.model.AttackLog;
import com.honeygrid.honeygrid.repository.AttackLogRepository;
import com.honeygrid.honeygrid.service.InputPolicy;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import java.util.*;

@RestController
@RequestMapping("/api/v1/threat-intel")
public class ThreatIntelExportController {
    private final AttackLogRepository repository;
    public ThreatIntelExportController(AttackLogRepository repository) { this.repository=repository; }
    private List<AttackLog> page(int page) {
        if(page<0 || page>100000) throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        return repository.findAll(PageRequest.of(page,1000,Sort.by("id").ascending())).getContent();
    }
    @GetMapping(value="/export/plain-ips",produces=MediaType.TEXT_PLAIN_VALUE)
    public String exportPlainIps(@RequestParam(defaultValue="0") int page) {
        Set<String> ips=new LinkedHashSet<>();
        for(var log:page(page)) ips.add(log.getIpAddress());
        return String.join("\n",ips);
    }
    @GetMapping(value="/export/stix2",produces=MediaType.APPLICATION_JSON_VALUE)
    public Map<String,Object> exportStix2(@RequestParam(defaultValue="0") int page) {
        List<Map<String,Object>> objects=new ArrayList<>();
        for(var log:page(page)) {
            String ip=InputPolicy.ip(log.getIpAddress());
            String type=ip.contains(":") ? "ipv6-addr" : "ipv4-addr";
            // A connection is an observation, not sufficient evidence for a malicious indicator.
            String addressId=type+"--"+UUID.randomUUID();
            objects.add(Map.of("type",type,"spec_version","2.1","id",addressId,"value",ip));
            String time=new java.time.format.DateTimeFormatterBuilder().appendInstant(3).toFormatter().format(log.getTimestamp().toInstant());
            objects.add(Map.of("type","observed-data","spec_version","2.1","id","observed-data--"+UUID.randomUUID(),
                "created",time,"modified",time,"first_observed",time,"last_observed",time,
                "number_observed",1,"object_refs",List.of(addressId)));
        }
        return Map.of("type","bundle","id","bundle--"+UUID.randomUUID(),"objects",objects);
    }
}
