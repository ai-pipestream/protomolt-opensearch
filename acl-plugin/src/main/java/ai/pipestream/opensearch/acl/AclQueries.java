package ai.pipestream.opensearch.acl;

import java.util.Collection;

import org.apache.lucene.search.join.ScoreMode;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;

/**
 * Builds the queries that limit results to documents the caller may read.
 */
public final class AclQueries {

    private AclQueries() {
    }

    /**
     * Builds the access query: the ACL is complete, the allow field holds one of the caller's principals, and no
     * gate lacks all of the caller's principals, and the deny field holds none of the caller's principals. With no
     * principals it matches nothing.
     *
     * @param fields the ACL field names
     * @param principals the caller's principal keys
     * @return the access query
     */
    public static QueryBuilder access(AclFields fields, Collection<String> principals) {
        if (principals.isEmpty()) {
            return QueryBuilders.boolQuery().mustNot(QueryBuilders.matchAllQuery());
        }
        QueryBuilder gateFails = QueryBuilders.boolQuery()
                .mustNot(QueryBuilders.termsQuery(fields.gateAllowPath(), principals));
        return QueryBuilders.boolQuery()
                .filter(QueryBuilders.termQuery(fields.complete(), true))
                .filter(QueryBuilders.termsQuery(fields.allow(), principals))
                .mustNot(QueryBuilders.termsQuery(fields.deny(), principals))
                .mustNot(QueryBuilders.nestedQuery(fields.gates(), gateFails, ScoreMode.None).ignoreUnmapped(true));
    }

    /**
     * Builds the access query applied only to documents of the protected indices; documents of other indices
     * pass unchanged.
     *
     * @param fields the ACL field names
     * @param principals the caller's principal keys
     * @param protectedIndices concrete names of the protected indices in the request
     * @return the scoped access query
     */
    public static QueryBuilder accessForIndices(
            AclFields fields, Collection<String> principals, Collection<String> protectedIndices) {
        return QueryBuilders.boolQuery()
                .should(access(fields, principals))
                .should(QueryBuilders.boolQuery().mustNot(QueryBuilders.termsQuery("_index", protectedIndices)))
                .minimumShouldMatch(1);
    }

    /**
     * Combines the caller's query with the access query as a filter.
     *
     * @param original the caller's query, or null for match all
     * @param access the access query
     * @return the combined query
     */
    public static QueryBuilder restrict(QueryBuilder original, QueryBuilder access) {
        BoolQueryBuilder combined = QueryBuilders.boolQuery().filter(access);
        if (original != null) {
            combined.must(original);
        }
        return combined;
    }
}
